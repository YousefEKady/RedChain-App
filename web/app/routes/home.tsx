import type { Route } from "./+types/home";
import Dashboard from "../components/Dashboard";

export function meta({}: Route.MetaArgs) {
  return [
    { title: "Red Team Automation Dashboard" },
    { name: "description", content: "Manage your security engagements and view reports" },
  ];
}

export default function Home() {
  return <Dashboard />;
}
