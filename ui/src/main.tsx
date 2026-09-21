// The shell. A router and two routes, and NOTHING ELSE: no auth provider, no
// account gate, no analytics. The box this page came from is the identity --
// komizo ui binds loopback or the tailnet interface, and being able to open
// the page is being allowed to see it.
import { render } from "solid-js/web";
import { Route, Router } from "@solidjs/router";
import "./index.css";
import Overview from "./routes/Overview";
import AppDetail from "./routes/AppDetail";
render(
  () => (
    <Router>
      <Route path="/" component={Overview} />
      <Route path="/app/:name" component={AppDetail} />
    </Router>
  ),
  document.getElementById("root")!,
);
