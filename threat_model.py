"""Generate the Phase 1 capstone report using the Python standard library."""

from collections import Counter
from pathlib import Path


def main():
    asset_rows = [
        ("A01","Workload token","IAM","C/I","Service impersonation and unauthorized actions"),
        ("A02","LLM endpoint and quota","AI Platform","I/A","Service disruption and excess spend"),
        ("A03","Vector index and metadata","Data Platform","C/I/A","Sensitive retrieval or poisoned answers"),
        ("A04","CI/CD pipeline","Release Engineering","I/A","Unapproved production release"),
        ("A05","Support transcripts","Data Owner","C/I","Customer confidentiality breach"),
        ("A06","Source and infrastructure code","Engineering","C/I","Exposure of internals or unsafe changes"),
        ("A07","Model and prompt configuration","AI Platform","I/A","Incorrect or unsafe outputs"),
        ("A08","Audit trail","Security Operations","C/I/A","Sensitive log exposure or lost forensic evidence"),
        ("A09","Signing and encryption keys","Key Management","C/I/A","Forged releases or loss of data access"),
        ("A10","API workload","Application Platform","I/A","Unauthorized changes or downtime"),
        ("A11","User sessions","IAM","C/I","Account impersonation"),
        ("A12","Verified backups","Data Platform","C/I/A","Failure to recover trusted content"),
    ]
    assets = [dict(zip(("id","asset","owner","cia","impact"), row)) for row in asset_rows]

    # 1 = unlikely or minor, 3 = plausible or material, 5 = expected or severe.
    # Values between anchors are judgment calls. Score scenarios linked to assets.
    initial_risks = [
        ("R1","A01","Identity","Broad workload role","A stolen workload token is replayed","Cross-cloud data access expands",4,5,
         "Assume a replayable token and broad role. Inspect token lifetime and effective grants."),
        ("R2","A02","API","No per-user usage limits","An authenticated caller floods inference","Staff lose access and spend rises",3,4,
         "Assume shared quota. Test capped usage in a sandbox."),
        ("R3","A05","Data","Retrieval skips document authorization","A low-privilege user requests another team's record","Customer information is exposed",4,5,
         "Assume a shared index. Run a two-role retrieval test."),
        ("R4","A04","Supply chain","Untrusted build code can publish or deploy","A modified dependency or workflow executes in CI","An altered release reaches production",3,5,
         "Assume build and release share authority. Inspect CI trust and admission rules."),
        ("R5","A10","Network","A management path accepts broad ingress","An external actor reaches a weak management endpoint","A service instance is compromised",2,4,
         "Assume this separate exposure for Day 1. Verify actual ingress and reachability."),
    ]
    for asset in assets:
        print(f"{asset['id']} | {asset['asset']} | {asset['cia']} | {asset['owner']} | {asset['impact']}")
    print("\nRisk statements")
    for rid, aid, layer, weakness, actor, impact, likelihood, severity, evidence in initial_risks:
        print(f"{rid} ({layer}, {aid}): Because {weakness}, {actor.lower()}, causing this outcome: {impact}.")
    print("\nTop three provisional risks")
    for risk in sorted(initial_risks, key=lambda row: row[6] * row[7], reverse=True)[:3]:
        print(f"{risk[0]}: {risk[6]} × {risk[7]} = {risk[6] * risk[7]}. {risk[8]}")

    # Each threat ties to a boundary, a weakness, an asset and a proposed control.
    # Final columns are baseline likelihood, impact, target likelihood and target impact.
    threat_rows = [
        ("T1","Spoofing","B2","A01","Replayable workload credential and broad trust","Attacker impersonates API across clouds","C1",4,5,2,5),
        ("T2","Tampering","B5","A03","Ingestion accepts unreviewed content","Malicious text poisons retrieved context","C4",3,4,2,4),
        ("T3","Repudiation","B6","A08","Publisher or deploy event lacks actor attribution","Investigators cannot attribute changes","C7",3,4,1,4),
        ("T4","Information Disclosure","B3","A05","Retriever trusts query scope supplied by caller","User retrieves another team's transcript","C2",4,5,2,5),
        ("T5","Denial of Service","B4","A02","Inference quota is shared and unbounded per caller","Requests consume capacity and increase spend","C5",3,4,2,3),
        ("T6","Elevation of Privilege","B5","A04","Build identity can deploy directly","Compromised build gains production authority","C3",3,5,1,5),
    ]
    threat_keys = ("id","stride","boundary","asset","weakness","scenario","control","likelihood","impact","target_likelihood","target_impact")
    threats = [dict(zip(threat_keys, row)) for row in threat_rows]
    for threat in threats:
        threat["score"] = threat["likelihood"] * threat["impact"]
        threat["target_score"] = threat["target_likelihood"] * threat["target_impact"]
        print(threat["id"], threat["stride"], threat["score"], "→", threat["target_score"])

    # Each transition includes a condition and a proposed barrier.
    attack_paths = [
        ("P1", "Workload credential replay", ["T1","T4"], [
            ("Exposed API","Code execution","Assume exploitable input-handling defect","C6"),
            ("Code execution","Stolen token","Runtime exposes reusable credentials","C1"),
            ("Stolen token","Retriever access","Federation accepts replayable token and broad subject","C1"),
            ("Retriever access","Transcript access","Retriever fails to enforce caller entitlement","C2"),
            ("Transcript access","Customer records are exposed","Retrieved text can leave through an API response","C2"),
        ]),
        ("P2", "Compromised release", ["T6","T3"], [
            ("Exposed build workflow","Build execution","Build runs an untrusted dependency or change","C12"),
            ("Build execution","Deploy authority","Build identity can assume production release role","C3"),
            ("Deploy authority","Modified API workload","Admission accepts unapproved artifact","C3"),
            ("Modified API workload","Query interception","Release serves real traffic without a smoke-test gate","C13"),
            ("Query interception","Support data may be exposed","Malicious runtime can forward query content","C11"),
        ]),
        ("P3", "Poisoned RAG content", ["T2"], [
            ("Publisher portal","Publisher session","Publisher account is phished","C14"),
            ("Publisher session","Content accepted","One account can approve and publish","C4"),
            ("Content accepted","Indexed instructions","Ingestion accepts unapproved document versions","C4"),
            ("Indexed instructions","Manipulated answer","Application passes chunks as context without safeguards","C15"),
            ("Manipulated answer","Support staff act on incorrect guidance","Workflow treats model text as an authoritative instruction","C15"),
        ]),
    ]
    for pid, name, links, edges in attack_paths:
        print(pid, name, links)
        for source, target, condition, barrier in edges:
            print(f"  {source} → {target} | {condition} | {barrier}")

    control_rows = [
        ("C1","Prevent","Identity","IAM","Bind federated trust to issuer, subject and audience. Use scoped short-lived credentials and isolate credential access.","Unapproved issuer, subject and audience fail exchange; test replay within lifetime."),
        ("C2","Prevent","Data","Data Platform","Enforce server-side per-document authorization using verified caller context and reject unauthorized content before inference.","Two-role cross-team test returns zero protected chunks."),
        ("C3","Prevent","Pipeline","Release Engineering","Separate build and release identities. Require independent approval and verify trusted provenance at deploy.","Build identity cannot deploy. Unapproved digest is rejected."),
        ("C4","Prevent","Data","Data Platform","Require independent approval of content and ingest only approved document versions.","Unapproved upload cannot be indexed."),
        ("C5","Prevent","API","AI Platform","Apply per-user request size and usage caps with a bounded fallback.","Synthetic burst is capped and fallback stays usable."),
        ("C6","Prevent","Application","App Team","Constrain inputs and patch exploitable API dependencies.","Regression input fails safely and deployed digest passes review."),
        ("C7","Detect","Monitoring","Security Operations","Correlate actor, request ID, deployment digest and policy outcome. Alert on missing attribution or abnormal activity.","Synthetic unattributed change opens a routed alert with a trace ID."),
        ("C8","Respond","Incident Response","Security Operations","Disable affected access, contain the workload, revoke sessions where supported and investigate using preserved evidence.","Tabletop measures isolation and tests whether issued credentials still work."),
        ("C9","Recover","Data","Data Platform","Rebuild the index from a verified snapshot and recheck access rules before reopening.","Restore drill validates sample document hashes and cross-team denials."),
        ("C10","Recover","Pipeline","Release Engineering","Redeploy a verified known-good image and verify release and query behavior.","Rollback drill proves expected digest and passes synthetic queries."),
        ("C11","Prevent","Network","Cloud Platform","Deny unnecessary outbound destinations from the API runtime.","Approved endpoints work and an unapproved test destination fails."),
        ("C12","Prevent","Pipeline","Release Engineering","Pin reviewed dependencies and isolate untrusted build jobs.","Untrusted job runs without publish or release credentials."),
        ("C13","Prevent","Workload","App Team","Gate rollout with synthetic smoke tests before routing production traffic.","A deliberately failing smoke test blocks rollout."),
        ("C14","Prevent","Identity","IAM","Require phishing-resistant authentication for publisher roles.","Publisher role denies a login using an unapproved authenticator."),
        ("C15","Prevent","AI Application","AI Platform","Treat retrieved chunks as untrusted. Keep the model read-only and require human confirmation for sensitive actions based on answers.","Malicious sample cannot trigger a tool action; staff can inspect citations."),
        ("C16","Detect","Monitoring","AI Platform","Alert on sustained quota pressure, bursts or elevated rejection rates.","Synthetic quota exercise routes an alert to the on-call owner."),
    ]
    control_keys = ("id","phase","layer","owner","design","evidence")
    controls = [dict(zip(control_keys, row)) for row in control_rows]
    print(Counter(control["phase"] for control in controls))
    print("Gap review: prove each alert arrives and exercise both clean-image and clean-index recovery.")

    boundaries = [
        ("B1","Employee and identity provider → Azure API","User token and question","Verify identity and route permission"),
        ("B2","Azure API → AWS retrieval service","Scoped federated identity, query, verified user context","Validate federation and independent caller context"),
        ("B3","AWS retrieval service → index and object store","Authorized chunks and document metadata","Enforce document permissions and restrict service role"),
        ("B4","Azure API → GCP managed model","Minimized prompt and authorized chunks","Verify workload and model scope, approved data handling and retention"),
        ("B5","Publisher / CI release → data and production","Reviewed document versions and signed artifacts","Separate approval, build and deployment authority"),
        ("B6","Cloud workloads → security monitoring","Redacted audit and alert events","Restrict access and require attributable audit trails"),
    ]
    architecture = (
        'flowchart TD\n'
        '    U[Employee] -->|B1 request| A[Azure API]\n'
        '    I[Company IdP] -->|B1 user token| A\n'
        '    A -->|B2 query and caller context| R[AWS retriever]\n'
        '    R -->|B3 authorized lookup| D[AWS index and document store]\n'
        '    D -->|B3 matched chunks| R\n'
        '    R -->|B2 authorized chunks| A\n'
        '    A -->|B4 minimized prompt| M[GCP managed LLM]\n'
        '    M -->|B4 answer| A\n'
        '    A -->|B1 answer| U\n'
        '    P[Publisher workflow] -->|B5 approved content| D\n'
        '    C[CI release pipeline] -->|B5 approved artifact| A\n'
        '    A -->|B6 audit metadata| S[Security monitoring]\n'
        '    R -->|B6 audit metadata| S\n'
        '    M -->|B6 usage telemetry| S\n'
        '    C -->|B6 release audit| S\n'
    )
    assumptions = [
        "Fictional internal support assistant. Azure hosts the API, AWS hosts retrieval and data, and GCP hosts managed inference. Provider-specific service selections, feature support, region and retention are design questions.",
        "The app retrieves authorized documents before invoking the model. The model has no direct data-store credentials and no write-capable tools. Identity, publishing, CI/CD and telemetry are separate flows.",
        "Employees, publishers, developers, release approvers, responders and workload identities are distinct actors. The baseline assumes the weaknesses in the register. Controls are proposed.",
        "In scope are request, document ingestion, release and audit flows. Employee endpoint internals, provider internals and model training are outside the review.",
        "Numbers use a training scale from 1 to 5. Baseline scores assume the listed weaknesses. Target scores are estimates conditional on control tests passing. They do not establish observed control effectiveness.",
    ]
    remediations = [
        ("1","Before pilot","T4","C2","Data Platform","Pass two-role retrieval tests for every protected namespace."),
        ("2","Before pilot","T1","C1","IAM","Reject unexpected federation claims and document the valid-token replay window."),
        ("3","Before production","T6","C3","Release Engineering","Demonstrate separation of duties and reject an unapproved artifact."),
        ("4","Before production","T2 / T3 / T5","C4 / C7 / C5 / C16","Data, Security Operations and AI Platform","Exercise publishing approval, alert routing and capped inference."),
    ]
    residual_risk = [
        "A valid in-scope token may still be replayable during its lifetime. Verify compensating detection and containment with IAM.",
        "Authorized users may misuse information they can legitimately retrieve. Data ownership and monitoring remain necessary.",
        "Subtle poisoning can survive review and model output can still mislead. Test with synthetic adversarial documents and maintain human review.",
        "Provider disruption and shared regional capacity can still reduce availability. Validate fallback and restore objectives with the service owner.",
    ]
    executive_summary = (
        'The proposed assistant answers internal support questions using company documents across three cloud environments. It handles sensitive support records, so an access-control error can expose customer information. A compromised release could alter what the service runs or forwards.\n'
        '\n'
        'The two highest baseline risks are replay of a workload credential and cross-team document disclosure, each scored 20 out of 25 in this training model. A build job with production authority follows at 15. These are scenario estimates based on explicit assumptions.\n'
        '\n'
        'Before a pilot, the Data Platform and IAM teams should prove that users cannot retrieve other teams’ records and that unexpected workload identities are rejected. Before production, Release Engineering should show that a build job cannot deploy directly and that only an independently approved artifact can enter production. Security Operations and the platform teams should run a containment and recovery exercise, including a clean redeployment and index restore.\n'
        '\n'
        'Request approval for a synthetic-data pilot once the pre-pilot evidence is recorded. Ask the service owner to review remaining valid-token replay, legitimate-access misuse and inaccurate model answers before expanding scope. Proposed controls and target scores require validation in the selected environment.'
    )
    capstone = {
        "architecture": architecture, "assumptions": assumptions, "critical_assets": assets,
        "trust_boundaries": boundaries, "threats": threats, "attack_paths": attack_paths,
        "controls": controls, "top_remediations": remediations, "residual_risk": residual_risk,
        "executive_summary": executive_summary,
    }
    asset_ids = {asset["id"] for asset in assets}
    boundary_ids = {boundary[0] for boundary in boundaries}
    control_ids = {control["id"] for control in controls}
    threat_ids = {threat["id"] for threat in threats}
    assert len(asset_ids) == len(assets) and 10 <= len(assets) <= 15
    assert len(threat_ids) == len(threats) == len({t["stride"] for t in threats}) == 6
    assert len(control_ids) == len(controls)
    assert all(t["asset"] in asset_ids and t["boundary"] in boundary_ids
               and t["control"] in control_ids for t in threats)
    assert len(attack_paths) == 3
    for pid, name, links, edges in attack_paths:
        assert set(links) <= threat_ids and len(edges) >= 4
        assert all(edge[3] in control_ids for edge in edges)
        assert all(left[1] == right[0] for left, right in zip(edges, edges[1:]))
    assert {c["phase"] for c in controls} == {"Prevent","Detect","Respond","Recover"}
    non_network = sum(c["layer"] != "Network" for c in controls)
    assert non_network * 2 >= len(controls)

    def table(headers, rows):
        lines = ["| " + " | ".join(headers) + " |",
                 "| " + " | ".join("---" for _ in headers) + " |"]
        lines.extend("| " + " | ".join(str(v).replace("|", chr(92) + "|") for v in row) + " |" for row in rows)
        return "\n".join(lines)

    def bullets(items):
        return "\n".join(f"- {item}" for item in items)

    sections = [
        "# Multi-Cloud GenAI Threat Model",
        "Worked Phase 1 capstone · Mahesh Dommati · Fictional design",
        "## Executive summary",
        executive_summary,
        "## Scope and assumptions",
        bullets(assumptions),
        "## Architecture and trust boundaries",
        "```mermaid\n" + architecture.strip() + "\n```",
        table(("ID","Boundary","Crossing","Verification"), boundaries),
        "## Critical assets",
        table(("ID","Asset","Owner","CIA","Business impact"), asset_rows),
        "## Threat register",
        "Each score is likelihood × impact. Read target scores as conditional estimates after validation.",
        table(("ID","STRIDE","Boundary","Asset","Weakness","Scenario","Baseline","Target","Control"),
              ((t["id"],t["stride"],t["boundary"],t["asset"],t["weakness"],t["scenario"],
                f'{t["likelihood"]} × {t["impact"]} = {t["score"]}',
                f'{t["target_likelihood"]} × {t["target_impact"]} = {t["target_score"]}',t["control"]) for t in threats)),
        "## Attack paths",
    ]
    for pid, name, links, edges in attack_paths:
        sections.extend([f"### {pid} · {name}", "Related threats " + ", ".join(links),
                         table(("From","To","Prerequisite","Proposed barrier"), edges)])
    sections.extend([
        "## Control map",
        f"{non_network} of {len(controls)} distinct controls come from layers outside network security.",
        table(("ID","Phase","Layer","Owner","Design","Evidence to collect"), control_rows),
        "For P1, investigate token and retrieval anomalies using C7, contain access with C8 and verify a clean runtime with C10. For P2, correlate release evidence using C7, contain the release with C8 and redeploy using C10. For P3, correlate publishing events using C7, stop ingestion with C8 and restore trusted content with C9.",
        "## Remediation priorities",
        table(("Priority","Gate","Threats","Controls","Owner","Exit evidence"), remediations),
        "## Residual risk and open validation",
        bullets(residual_risk),
    ])
    Path("Phase1_Multi_Cloud_Threat_Model.md").write_text("\n\n".join(sections) + "\n", encoding="utf-8")
    print(f"Validated {len(assets)} assets, {len(threats)} STRIDE threats, {len(attack_paths)} paths and {len(controls)} controls.")
    print("Exported Phase1_Multi_Cloud_Threat_Model.md to the current working directory.")


if __name__ == "__main__":
    main()
