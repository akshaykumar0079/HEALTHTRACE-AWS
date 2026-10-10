import { PageHeader } from "@/components/ui";
import { IncidentTable } from "@/components/IncidentTable";
import { SimulatedBadge } from "@/components/StatusStrip";

export default function Incidents() {
  return (
    <div className="space-y-5">
      <PageHeader
        title="Incidents"
        description="Actionable incidents. Repeats of the same problem are grouped into one incident with their evidence; raw log lines live under Live Events."
        actions={<SimulatedBadge />}
      />
      <IncidentTable preset="active" />
    </div>
  );
}
