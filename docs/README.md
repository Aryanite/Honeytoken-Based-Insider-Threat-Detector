# CyberGuard SOC: Documentation Index & Repository Reference

Welcome to the comprehensive documentation repository for the **Honeytoken-Based Insider Threat Detector (CyberGuard SOC)**.

This index organizes all architectural specifications, data contracts, empirical benchmarks, presentation guides, and individual engineering logs.

---

## 1. Architecture & Core Specifications

Detailed technical design, dynamic risk scoring formulation, and API data contracts.

| Document | Description | Primary Owner |
|:---|:---|:---:|
| [**System Model Architecture & Process Flowchart**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/architecture/MODEL_ARCHITECTURE_AND_FLOWCHART.md) | Comprehensive 8-layer architectural breakdown, Mermaid execution flowcharts, $W \times C \times F$ mathematical formulation, and relational ER diagrams. | Aryan Singh & Aniket Tiwari |
| [**Team-Wide API & Data Contract**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/architecture/contract.md) | Standardized JSON envelopes, ORM entity definitions (`HoneyToken`, `TokenTrigger`, `AlertLog`), route prefixes, and HTTP status codes. | Aryan Singh |

---

## 2. Presentation & Live Demonstration

Materials prepared for the project evaluation and faculty defense.

| Document | Description | Target Audience |
|:---|:---|:---:|
| [**Executive Presentation & Layer Walkthrough**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/presentation/EXPLANATION_FOR_SIR.md) | Plain-English, step-by-step breakdown of how each pipeline layer operates, complete with real-world incident scenarios and walkthroughs. | Faculty Supervisor & Evaluators |
| [**Interactive Flowchart Viewer**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/presentation/flowchart_viewer.html) | Standalone interactive HTML visualizer rendering the complete end-to-end telemetry and triage flowchart with Mermaid.js. | Live Demonstration |

---

## 3. Empirical Benchmarks & Evaluation

Quantitative performance data, micro-latency measurements, and triage accuracy.

| Document | Description | Key Findings |
|:---|:---|:---:|
| [**Performance & Evaluation Report**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/evaluation/performance_and_evaluation.md) | Empirical micro-latency benchmarks, sliding-window rate limit resistance, and triage accuracy comparisons against legacy honeypots. | **< 15 ms** average triage latency, **100%** threat capture rate. |

---

## 4. Engineering Team Work Logs

Individual contribution records detailing module ownership, git commits, code architecture, and test verification.

| Team Member | Roll Number | Role | Work Log |
|:---|:---:|:---|:---:|
| **Aryan Singh** | `2410031399` | Backend Lead & Architecture | [**Aryan_Work.md**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/team/Aryan_Work.md) |
| **Aniket Tiwari** | `2410031403` | Listener Engine, Decoy Generation & Simulation Lead | [**Aniket_Work.md**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/team/Aniket_Work.md) |
| **Sana Khan** | `2410031378` | Validation Schemas, API Contracts & Triage Analytics Lead | [**Sana_Work.md**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/team/Sana_Work.md) |
| **Saumya Kashyap** | `2410031737` | Decoy Artifact Templates, Ethical Framing & Containment UI | [**Saumya_Work.md**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/team/Saumya_Work.md) |

---

## 5. Engineering Roadmaps & Implementation Plans

Historical and final planning documents tracking the project from initial prototype to final production SOC.

| Document | Scope |
|:---|:---|
| [**Final Master Plan**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/plans/finalplan.md) | Approved step-by-step master roadmap for dynamic risk scoring, decoy synthesis, and test suites. |
| [**Original Project Plan**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/plans/Plan.md) | Baseline milestone breakdown across weekly development phases. |
| [**Technical Plan**](file:///c:/Users/as113/Downloads/Honeytoken-Based-Insider-Threat-Detector/Honeytoken-Based-Insider-Threat-Detector/docs/plans/honeytoken-insider-threat-detector-plan.md) | Initial technical design document for FastAPI backend and deception deployment. |
