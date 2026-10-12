import { Router, type IRouter } from "express";
import healthRouter from "./health";
import securityRouter from "./security";

const router: IRouter = Router();

router.get("/", (req, res) => {
  if (req.accepts("html") && !req.accepts("json")) {
    return res.redirect("http://localhost:5173/");
  }
  res.json({
    status: "online",
    system: "Sentinel AI Privacy & Security Reinforcement Engine",
    version: "2.1.0",
    dashboardUrl: "http://localhost:5173/",
    message: "Sentinel API is operational. Open http://localhost:5173 in your browser to access the graphical security command dashboard.",
    endpoints: {
      health: "/api/healthz",
      auth: "/api/auth/me",
      dashboard: "/api/dashboard",
      zeroTrust: "/api/zero-trust/assessment",
      dpSgd: "/api/privacy/dp-sgd/benchmarks",
      gruIntrusion: "/api/intrusion/events",
      blockchain: "/api/blockchain/blocks",
      encryption: "/api/encryption/status",
      markovDefense: "/api/defense/markov-state",
    },
  });
});

router.use(healthRouter);
router.use(securityRouter);

export default router;
