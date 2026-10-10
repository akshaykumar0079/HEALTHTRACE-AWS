import { StrictMode, lazy } from "react";
import { createRoot } from "react-dom/client";
import { Navigate, createBrowserRouter, RouterProvider, useParams } from "react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./index.css";
import AppShell from "./app/AppShell";
import { RouteError } from "./app/RouteError";

const Landing = lazy(() => import("./pages/Landing"));
const Overview = lazy(() => import("./pages/Overview"));
const Incidents = lazy(() => import("./pages/Incidents"));
const Pinned = lazy(() => import("./pages/Pinned"));
const History = lazy(() => import("./pages/History"));
const LiveEvents = lazy(() => import("./pages/LiveEvents"));
const Pulse = lazy(() => import("./pages/Dashboard"));
const Monitor = lazy(() => import("./pages/Monitor"));
const Investigation = lazy(() => import("./pages/Investigation"));
const Alerts = lazy(() => import("./pages/Alerts"));
const Logs = lazy(() => import("./pages/Logs"));
const Analytics = lazy(() => import("./pages/Analytics"));
const Services = lazy(() => import("./pages/Services"));
const ServiceDetail = lazy(() => import("./pages/ServiceDetail"));
const Aws = lazy(() => import("./pages/Aws"));
const Settings = lazy(() => import("./pages/Settings"));
const Simulator = lazy(() => import("./pages/Simulator"));

function LegacyIncidentRedirect() {
  const { id } = useParams();
  return <Navigate to={`/app/incidents/${id ?? ""}`} replace />;
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false, staleTime: 5_000 },
  },
});

const router = createBrowserRouter([
  { path: "/", element: <Landing />, errorElement: <RouteError /> },
  {
    path: "/app",
    element: <AppShell />,
    errorElement: <RouteError />,
    children: [
      { index: true, element: <Overview /> },
      { path: "incidents", element: <Incidents /> },
      { path: "incidents/:id", element: <Investigation /> },
      { path: "pinned", element: <Pinned /> },
      { path: "history", element: <History /> },
      { path: "events", element: <LiveEvents /> },
      { path: "pulse", element: <Pulse /> },
      { path: "monitor", element: <Monitor /> },
      // Older links and bookmarks.
      { path: "anomalies", element: <Navigate to="/app/incidents" replace /> },
      { path: "anomalies/:id", element: <LegacyIncidentRedirect /> },
      { path: "alerts", element: <Alerts /> },
      { path: "logs", element: <Logs /> },
      { path: "analytics", element: <Analytics /> },
      { path: "services", element: <Services /> },
      { path: "services/:name", element: <ServiceDetail /> },
      { path: "aws", element: <Aws /> },
      { path: "simulator", element: <Simulator /> },
      { path: "settings", element: <Settings /> },
    ],
  },
  { path: "*", element: <RouteError notFound /> },
]);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
