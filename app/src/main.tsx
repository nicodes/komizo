import {render} from "solid-js/web";
import {Route, Router} from "@solidjs/router";
import "./index.css";
import Overview from "./routes/Overview";
import AppDetail from "./routes/AppDetail";
render(() => <Router><Route path="/" component={Overview}/><Route path="/app/:application/:instance" component={AppDetail}/></Router>, document.getElementById("root")!);
