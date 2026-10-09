# Authorized implementation

Implement the 2026-10-09 technical review and T01–T24 development plan, retaining the C/Rust/Tauri/Svelte/Axum stack and compatibility. Baseline: `126ba3a6f3760f56dfff954a06927a0707ea2821`.

Invariants: one live attempt per profile; stop retains ownership until reaping; no lost successful saves; profile/secret paired recovery; shared strict byte validation; CA plus DNS/IP identity or explicit SHA-256 pin; truthful readiness; network changes require ownership; no secret diagnostics; no fake successful login; conservative capability fallback.

User authorized full local implementation on 2026-10-09. External signing credentials, disposable Linux/Windows/macOS network test machines and real FortiGate credentials are not present. Continue independent work; do not claim unperformed platform/gateway acceptance. No release publication is authorized.
