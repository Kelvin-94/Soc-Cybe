/*
SOC-CyBe Security Platform
Module: Dashboard Entry Page

Purpose:
This page renders the main SOC dashboard shell. It is intentionally thin so
the dashboard implementation can evolve in its own component file.
*/

import { DashboardShell } from "@/components/dashboard-shell";

export default function Home() {
  /* Keeping the route component simple makes the dashboard easier to test,
     replace, or split into sub-views later. */
  return <DashboardShell />;
}
