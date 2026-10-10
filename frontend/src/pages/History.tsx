import { PageHeader } from "@/components/ui";
import { IncidentTable } from "@/components/IncidentTable";

export default function History() {
  return (
    <div className="space-y-5">
      <PageHeader
        title="History"
        description="Resolved incidents. They are kept, with their evidence and timeline, and stay searchable."
      />
      <IncidentTable preset="history" />
    </div>
  );
}
