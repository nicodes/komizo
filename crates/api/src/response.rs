use axum::{body::Body, response::Response};
use tokio::sync::OwnedSemaphorePermit;
struct HeldBody {
    body: Body,
    _permit: OwnedSemaphorePermit,
}
impl http_body::Body for HeldBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        std::pin::Pin::new(&mut self.get_mut().body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}
pub fn hold(response: Response, permit: OwnedSemaphorePermit) -> Response {
    response.map(|body| {
        Body::new(HeldBody {
            body,
            _permit: permit,
        })
    })
}
