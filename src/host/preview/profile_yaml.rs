//! Operator templates may use bounded YAML merge aliases; repository admission stays alias-free.
use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::parser::{Event, Parser};
struct Decoder {
    events: Vec<Event>,
    position: usize,
    anchors: BTreeMap<usize, Value>,
    budget: usize,
}
impl Decoder {
    fn charge(&mut self, bytes: usize) -> Result<()> {
        ensure!(bytes <= self.budget, "preview YAML exceeds expansion bound");
        self.budget -= bytes;
        Ok(())
    }
    fn node(&mut self, depth: usize) -> Result<Value> {
        ensure!(depth <= 32, "preview YAML nesting exceeds bound");
        let event = self
            .events
            .get(self.position)
            .cloned()
            .ok_or_else(|| anyhow!("incomplete preview YAML"))?;
        self.position += 1;
        let (anchor, value) = match event {
            Event::Alias(id) => {
                let value = self
                    .anchors
                    .get(&id)
                    .ok_or_else(|| anyhow!("unknown or recursive preview alias"))?;
                let size = serde_json::to_vec(value)?.len();
                self.charge(size)?;
                return Ok(self.anchors[&id].clone());
            }
            Event::Scalar(value, style, anchor, tag) => {
                let value = crate::workload::yaml::scalar(&value, style, tag.as_ref())?;
                self.charge(serde_json::to_vec(&value)?.len())?;
                (anchor, value)
            }
            Event::SequenceStart(anchor, tag) => {
                ensure!(
                    tag.is_none_or(|tag| tag.handle == "tag:yaml.org,2002:" && tag.suffix == "seq"),
                    "invalid preview sequence"
                );
                let mut values = vec![];
                while self.events.get(self.position) != Some(&Event::SequenceEnd) {
                    values.push(self.node(depth + 1)?);
                }
                self.position += 1;
                (anchor, values.into())
            }
            Event::MappingStart(anchor, tag) => {
                ensure!(
                    tag.is_none_or(|tag| tag.handle == "tag:yaml.org,2002:" && tag.suffix == "map"),
                    "invalid preview mapping"
                );
                let mut explicit = Map::new();
                let mut merged = Map::new();
                let mut seen = BTreeSet::new();
                while self.events.get(self.position) != Some(&Event::MappingEnd) {
                    let key = self.node(depth + 1)?;
                    let key = key
                        .as_str()
                        .ok_or_else(|| anyhow!("preview keys must be strings"))?
                        .to_owned();
                    ensure!(seen.insert(key.clone()), "duplicate preview YAML key");
                    let value = self.node(depth + 1)?;
                    if key == "<<" {
                        let sources = if let Value::Array(values) = value {
                            values
                        } else {
                            vec![value]
                        };
                        for source in sources {
                            let Value::Object(source) = source else {
                                bail!("invalid preview YAML merge")
                            };
                            for (key, value) in source {
                                merged.entry(key).or_insert(value);
                            }
                        }
                    } else {
                        explicit.insert(key, value);
                    }
                }
                self.position += 1;
                merged.extend(explicit);
                (anchor, merged.into())
            }
            _ => bail!("invalid preview YAML node"),
        };
        if anchor != 0 {
            self.charge(serde_json::to_vec(&value)?.len())?;
            ensure!(
                !self.anchors.contains_key(&anchor),
                "repeated preview YAML anchor"
            );
            self.anchors.insert(anchor, value.clone());
        }
        Ok(value)
    }
}
pub fn parse(body: &str) -> Result<Value> {
    ensure!(body.len() <= 1 << 20, "preview compose exceeds bound");
    let mut parser = Parser::new_from_str(body);
    let mut events = vec![];
    let mut documents = 0;
    loop {
        let (event, _) = parser
            .next_token()
            .map_err(|_| anyhow!("preview compose is invalid"))?;
        if event == Event::DocumentStart {
            documents += 1;
            ensure!(documents == 1, "preview compose requires one document");
        }
        let end = event == Event::StreamEnd;
        events.push(event);
        if end {
            break;
        }
        ensure!(
            events.len() <= 131072,
            "preview YAML node count exceeds bound"
        );
    }
    ensure!(
        events.first() == Some(&Event::StreamStart) && events.get(1) == Some(&Event::DocumentStart),
        "preview compose is invalid"
    );
    let mut decoder = Decoder {
        events,
        position: 2,
        anchors: BTreeMap::new(),
        budget: 8 << 20,
    };
    let value = decoder.node(0)?;
    ensure!(
        decoder.events.get(decoder.position) == Some(&Event::DocumentEnd)
            && decoder.events.get(decoder.position + 1) == Some(&Event::StreamEnd),
        "preview compose requires one document"
    );
    Ok(value)
}
