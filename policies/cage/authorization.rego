package cage.authorization

import data.cage.data_flow
import data.cage.graph
import data.cage.intent
import data.cage.provenance
import data.cage.resource
import data.cage.runtime
import data.cage.trajectory

# Collect all matched findings across modular sub-packages
matched_findings[f] {
    f := intent.findings[_]
}

matched_findings[f] {
    f := resource.findings[_]
}

matched_findings[f] {
    f := data_flow.findings[_]
}

matched_findings[f] {
    f := runtime.findings[_]
}

matched_findings[f] {
    f := graph.findings[_]
}

matched_findings[f] {
    f := provenance.findings[_]
}

matched_findings[f] {
    f := trajectory.findings[_]
}

# Export array of findings
findings = [f | f := matched_findings[_]]

