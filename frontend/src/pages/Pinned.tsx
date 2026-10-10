import { PageHeader } from "@/components/ui";
import { IncidentTable } from "@/components/IncidentTable";

export default function Pinned() {
  return (
    <div className="space-y-5">
      <PageHeader
        title="Pinned"
        description="Incidents you chose to keep in view, in any status. Pinning is only a bookmark: it never changes severity, risk score or status."
      />
      <IncidentTable preset="pinned" />
    </div>
  );
}
