#!/usr/bin/env python3
"""
CENTRIX ML Integration Architecture PDF Generator
=================================================
Generates a multi-page PDF document detailing the ML Threat Intel pipeline architecture
and an in-depth comparison explaining why RAG (Retrieval-Augmented Generation)
was selected over Model Fine-Tuning or External Dataset Training.
"""

import os
import sys
from pathlib import Path

class PDFBuilder:
    def __init__(self):
        self.objects = []

    def _add(self, content):
        obj_id = len(self.objects) + 1
        self.objects.append(content)
        return obj_id

    def build(self, filename="CENTRIX_ML_Integration_Architecture.pdf"):
        # Reserve Object 1 for Catalog and Object 2 for Pages
        self.objects = ["", ""]

        # Fonts (Objects 3, 4, 5)
        f_helvetica = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        f_bold = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        f_oblique = self._add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique /Encoding /WinAnsiEncoding >>")

        # Build Page Streams
        p1_content = self._build_page1()
        p2_content = self._build_page2()
        p3_content = self._build_page3()

        pages_data = [p1_content, p2_content, p3_content]
        page_ids = []

        font_res = f"<< /Font << /F1 {f_helvetica} 0 R /F2 {f_bold} 0 R /F3 {f_oblique} 0 R >> >>"

        for p_text in pages_data:
            b_text = p_text.replace("—", "-").replace("’", "'").replace("“", '"').replace("”", '"').replace("…", "...").replace("🔴", "*").replace("⚠️", "[WARNING]")
            s_bytes = b_text.encode("latin-1")
            s_id = self._add(f"<< /Length {len(s_bytes)} >>\nstream\n{b_text}\nendstream")
            p_id = self._add(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {s_id} 0 R /Resources {font_res} >>")
            page_ids.append(p_id)

        # Set Object 1 (Catalog) and Object 2 (Pages)
        kids_str = " ".join(f"{pid} 0 R" for pid in page_ids)
        self.objects[0] = "<< /Type /Catalog /Pages 2 0 R >>"
        self.objects[1] = f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_ids)} >>"

        # Write PDF File
        with open(filename, "wb") as f:
            f.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
            offsets = {}
            for idx, content in enumerate(self.objects, 1):
                offsets[idx] = f.tell()
                f.write(f"{idx} 0 obj\n{content}\nendobj\n".encode("latin-1"))

            xref_pos = f.tell()
            f.write(f"xref\n0 {len(self.objects) + 1}\n0000000000 65535 f \n".encode("latin-1"))
            for idx in range(1, len(self.objects) + 1):
                f.write(f"{offsets[idx]:010d} 00000 n \n".encode("latin-1"))

            f.write(f"trailer\n<< /Size {len(self.objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1"))

        print(f"[+] Successfully generated PDF whitepaper at: {Path(filename).resolve()}")

    def _text(self, c, text, x, y, font="F1", size=10, color="0 0 0"):
        clean = text.replace("(", "\\(").replace(")", "\\)")
        c.append(f"{color} rg BT /{font} {size} Tf 1 0 0 1 {x} {y} Tm ({clean}) Tj ET")

    def _draw_wrapped(self, c, text, x, y, font="F1", size=9.5, leading=13, width=540, color="0.2 0.25 0.33"):
        words = text.replace("\n\n", " \n\n ").split(" ")
        lines = []
        cur_line = []
        cur_w = 0
        char_w = size * 0.50

        for w in words:
            if w == "\n\n":
                lines.append(" ".join(cur_line))
                lines.append("")
                cur_line = []
                cur_w = 0
                continue
            w_w = len(w) * char_w
            if cur_w + w_w > width:
                lines.append(" ".join(cur_line))
                cur_line = [w]
                cur_w = w_w
            else:
                cur_line.append(w)
                cur_w += w_w + char_w

        if cur_line:
            lines.append(" ".join(cur_line))

        cur_y = y
        for line in lines:
            if line == "":
                cur_y -= leading * 0.5
                continue
            self._text(c, line, x, cur_y, font=font, size=size, color=color)
            cur_y -= leading

    def _build_page1(self):
        c = []
        # Header banner box
        c.append("0.06 0.09 0.16 rg 36 735 540 42 re f")
        self._text(c, "CENTRIX ML Threat Intelligence & Architecture", 48, 752, font="F2", size=16, color="1 1 1")
        self._text(c, "Whitepaper & Technical Rationale: RAG vs. Model Fine-Tuning & Custom Training", 48, 740, font="F3", size=9.5, color="0.7 0.88 0.98")

        # Divider line
        c.append("0.01 0.52 0.78 RG 2 w 36 725 m 576 725 l S")

        # Section 1: Executive Summary
        self._text(c, "1. Executive Summary & Architecture Overview", 36, 702, font="F2", size=13, color="0.06 0.09 0.16")

        summary_txt = (
            "The CENTRIX Threat Intelligence Engine integrates local machine learning capabilities to enrich security scan findings "
            "with deep, actionable vulnerability reasoning. The system combines local Large Language Model (LLM) reasoning via "
            "Ollama (qwen2.5-coder) with a high-performance vector store (ChromaDB) to achieve real-time, privacy-preserving threat intelligence "
            "without transmitting proprietary codebase findings to external cloud APIs."
        )
        self._draw_wrapped(c, summary_txt, 36, 686, font="F1", size=9.5, leading=13, width=540, color="0.2 0.25 0.33")

        # Core Modules Box
        c.append("0.96 0.98 1 rg 0.8 0.88 0.95 RG 1 w 36 515 540 115 re B")
        self._text(c, "Key Architecture Modules:", 46, 612, font="F2", size=10, color="0.06 0.09 0.16")

        modules = [
            ("Multi-Source Advisory Feeds:", "Automated sync for NVD (CVE API 2.0), GHSA (GraphQL), CISA-KEV, & Exploit-DB."),
            ("Language-Aware Normalization:", "Canonical AdvisoryRecord dataclass with language inference (Python, PHP, JS, etc.)."),
            ("ChromaDB Vector Store:", "Dense nomic-embed-text embeddings stored locally with metadata-level language filtering."),
            ("Automated Scan Enrichment:", "Stage 5 Analyze pipeline automatically enriches findings with structured JSON AI fields."),
            ("Anti-Hallucination Guardrails:", "Confidence badges (1-10) & automated warnings when cited CVEs miss retrieved context."),
        ]
        y_mod = 596
        for title, desc in modules:
            self._text(c, title, 46, y_mod, font="F2", size=8.5, color="0.01 0.52 0.78")
            self._text(c, desc, 185, y_mod, font="F1", size=8.5, color="0.1 0.1 0.1")
            y_mod -= 15

        # Section 2: Comparison Intro
        self._text(c, "2. Comparative Matrix: RAG vs. Fine-Tuning vs. Model Training", 36, 485, font="F2", size=13, color="0.06 0.09 0.16")
        intro_cmp = "A foundational design decision in building CENTRIX ML was evaluating whether to fine-tune an LLM, train a custom model on external security datasets, or implement Retrieval-Augmented Generation (RAG). The table below summarizes key operational trade-offs:"
        self._draw_wrapped(c, intro_cmp, 36, 468, font="F1", size=9.5, leading=13, width=540, color="0.2 0.25 0.33")

        # Draw Comparison Table
        y_tbl = 430
        c.append("0.06 0.09 0.16 rg 36 410 540 20 re f")
        self._text(c, "Evaluation Criteria", 42, 416, font="F2", size=8.5, color="1 1 1")
        self._text(c, "CENTRIX RAG Pipeline [Chosen]", 150, 416, font="F2", size=8.5, color="1 1 1")
        self._text(c, "LLM Fine-Tuning", 310, 416, font="F2", size=8.5, color="1 1 1")
        self._text(c, "Full Model Training", 440, 416, font="F2", size=8.5, color="1 1 1")

        rows = [
            ("Knowledge Recency\n(New CVEs/Zero-Days)", "INSTANT (Real-Time)\nDB updates in seconds without retraining.", "STALE / STATIC\nFrozen at training epoch. Retraining is expensive.", "STALE / STATIC\nTakes weeks/months to retrain model weights."),
            ("Hallucination Risk\n& Citation Audit", "STRICTLY GROUNDED\nDirect CVE citations & hallucination detection warnings.", "HIGH RISK\nGenerates plausible but fake CVE IDs and patch notes.", "HIGH RISK\nProne to hallucinating parameters & severity scores."),
            ("Catastrophic\nForgetting", "ZERO LOSS\nBase LLM retains full code parsing & JSON reasoning skills.", "SEVERE DEGRADATION\nFine-tuning degrades core code syntax & JSON formatting.", "HIGH RISK\nRequires massive multi-task dataset to avoid logic loss."),
            ("Data Privacy &\nAir-Gap Support", "100% LOCAL / ON-PREM\nVectors stay inside .wraith/chroma_db locally via Ollama.", "PRIVACY EXPOSURE\nRequires exporting logs/findings to training clusters.", "HIGH PRIVACY RISK\nExternal dataset pipeline exposure risks compliance."),
            ("Compute Cost &\nInfrastructure", "ULTRA LOW COST\nRuns on local developer CPU/GPU. $0 cluster training cost.", "HIGH COST\nRequires multi-GPU hardware (A100/H100) per update run.", "EXTREMELY EXPENSIVE\nMillions in compute, dataset labeling, and hardware."),
        ]

        y_r = 410
        h_row = 58
        for idx, (c1, c2, c3, c4) in enumerate(rows):
            y_r -= h_row
            bg_c = "0.96 0.98 1" if idx % 2 == 0 else "1 1 1"
            c.append(f"{bg_c} rg 36 {y_r} 540 {h_row} re f")
            c.append(f"0.8 0.85 0.9 RG 0.5 w 36 {y_r} 540 {h_row} re s")

            self._draw_wrapped(c, c1, 40, y_r + h_row - 12, font="F2", size=8, leading=10, width=105, color="0.06 0.09 0.16")
            self._draw_wrapped(c, c2, 150, y_r + h_row - 12, font="F1", size=7.5, leading=9.5, width=155, color="0.01 0.4 0.65")
            self._draw_wrapped(c, c3, 310, y_r + h_row - 12, font="F1", size=7.5, leading=9.5, width=125, color="0.2 0.2 0.2")
            self._draw_wrapped(c, c4, 440, y_r + h_row - 12, font="F1", size=7.5, leading=9.5, width=130, color="0.2 0.2 0.2")

        # Footer
        c.append("0.5 0.5 0.5 RG 0.5 w 36 30 m 576 30 l S")
        self._text(c, "CENTRIX Security Framework - ML Threat Intelligence Architecture Whitepaper", 36, 18, font="F1", size=8, color="0.4 0.4 0.4")
        self._text(c, "Page 1 of 3", 535, 18, font="F1", size=8, color="0.4 0.4 0.4")

        return "\n".join(c)

    def _build_page2(self):
        c = []
        # Header bar
        c.append("0.06 0.09 0.16 rg 36 745 540 28 re f")
        self._text(c, "3. Deep Technical Rationale: Why RAG Beats Fine-Tuning", 48, 754, font="F2", size=12, color="1 1 1")

        y = 720

        # Point A
        self._text(c, "A. Real-Time Zero-Day Adaptability vs. Static Training Cutoffs", 36, y, font="F2", size=11, color="0.01 0.52 0.78")
        y -= 16
        txt_a = (
            "Threat intelligence is an inherently dynamic domain. Public vulnerability repositories (NVD, GHSA, CISA-KEV) "
            "publish over 100 new CVEs and exploit proofs-of-concept every single day. Fine-tuned or custom-trained models "
            "suffer from immediate knowledge staleness because their knowledge base is strictly locked at their last training epoch. "
            "Retraining a model daily or weekly to incorporate new CVEs requires continuous GPU compute pipelines, dataset curation, "
            "and regression testing - making it operationally infeasible.\n\n"
            "CENTRIX RAG decouples knowledge storage from reasoning logic. When a new CVE or Exploit-DB entry is ingested into "
            "ChromaDB (via background feed sync or ingest_exploits.py), it is instantly searchable by the RAG engine within seconds. "
            "The underlying LLM (qwen2.5-coder) does not need to be retrained or modified to reason over brand new vulnerabilities."
        )
        self._draw_wrapped(c, txt_a, 36, y, font="F1", size=9, leading=12.5, width=540, color="0.2 0.25 0.33")
        y -= 115

        # Point B
        self._text(c, "B. Prevention of Catastrophic Forgetting & Format Instability", 36, y, font="F2", size=11, color="0.01 0.52 0.78")
        y -= 16
        txt_b = (
            "Fine-tuning a general-purpose coding LLM on security text datasets triggers 'catastrophic forgetting' - a phenomenon "
            "where the model's weight adjustments for vulnerability data degrade its general reasoning capabilities. Specifically, "
            "fine-tuned security models frequently lose the ability to parse complex multi-language source code syntax (Python, JS, Java) "
            "and fail to output strict JSON schemas required by automated security reporting pipelines.\n\n"
            "CENTRIX RAG preserves 100% of the base LLM's coding and instruction-following performance. The model receives raw "
            "unmodified source code alongside verbatim retrieved context chunks in the prompt, allowing it to apply pure reasoning "
            "without distorting its internal representations."
        )
        self._draw_wrapped(c, txt_b, 36, y, font="F1", size=9, leading=12.5, width=540, color="0.2 0.25 0.33")
        y -= 115

        # Point C
        self._text(c, "C. Elimination of Dangerous LLM Hallucinations in Audit Reports", 36, y, font="F2", size=11, color="0.01 0.52 0.78")
        y -= 16
        txt_c = (
            "In automated vulnerability assessments (VAPT), hallucinating a non-existent CVE ID or generating invalid exploit syntax "
            "destroys report credibility and wastes hundreds of engineering hours on false positives. Fine-tuned models predict text "
            "statistically, making them highly prone to inventing realistic-sounding but fake CVE numbers (e.g. 'CVE-2025-99999').\n\n"
            "CENTRIX RAG eliminates hallucination risks through a two-tier verification mechanism:\n"
            "1. Grounded Context Prompting: The LLM is strictly constrained to cite only CVEs present in the retrieved ChromaDB context.\n"
            "2. Automated Hallucination Detector: scanner/report_generator.py inspects LLM citations against retrieved advisories. "
            "If the model cites an uncited CVE, CENTRIX injects a prominent '[WARNING] Potential LLM Hallucination' banner in the final report."
        )
        self._draw_wrapped(c, txt_c, 36, y, font="F1", size=9, leading=12.5, width=540, color="0.2 0.25 0.33")
        y -= 130

        # Callout box on Page 2
        c.append(f"0.96 0.98 1 rg 0.01 0.52 0.78 RG 1 w 36 {y-45} 540 40 re B")
        callout = "Key Takeaway: RAG transforms the LLM from a fallible 'memory bank' into an intelligent, auditable reasoning engine that operates over verified, up-to-date threat intelligence vector stores."
        self._draw_wrapped(c, callout, 46, y-15, font="F3", size=8.5, leading=11.5, width=520, color="0.06 0.09 0.16")

        # Footer
        c.append("0.5 0.5 0.5 RG 0.5 w 36 30 m 576 30 l S")
        self._text(c, "CENTRIX Security Framework - ML Threat Intelligence Architecture Whitepaper", 36, 18, font="F1", size=8, color="0.4 0.4 0.4")
        self._text(c, "Page 2 of 3", 535, 18, font="F1", size=8, color="0.4 0.4 0.4")

        return "\n".join(c)

    def _build_page3(self):
        c = []
        # Header bar
        c.append("0.06 0.09 0.16 rg 36 745 540 28 re f")
        self._text(c, "4. Enterprise Privacy, Compliance & Integration Workflow", 48, 754, font="F2", size=12, color="1 1 1")

        y = 720

        # Point D
        self._text(c, "D. 100% On-Premise Air-Gap Compliance & Privacy", 36, y, font="F2", size=11, color="0.01 0.52 0.78")
        y -= 16
        txt_d = (
            "Enterprise vulnerability scanning requires absolute confidentiality. External dataset training or cloud-based fine-tuning "
            "requires transmitting internal audit findings, API endpoint signatures, and proprietary source code snippets to external cloud "
            "APIs or third-party training clusters - violating compliance mandates (SOC2, ISO27001, HIPAA, GDPR).\n\n"
            "CENTRIX ML operates 100% locally. Ollama runs local open-weights models (qwen2.5-coder), nomic-embed-text generates "
            "embeddings on-device, and ChromaDB stores vector indices inside .wraith/chroma_db. No data ever leaves the host system."
        )
        self._draw_wrapped(c, txt_d, 36, y, font="F1", size=9, leading=12.5, width=540, color="0.2 0.25 0.33")
        y -= 110

        # Section 5: Integration Diagram
        self._text(c, "5. Complete CENTRIX ML Data Flow & Workflow", 36, y, font="F2", size=13, color="0.06 0.09 0.16")
        y -= 20

        # Flow Diagram Box
        c.append(f"0.96 0.98 1 rg 0.8 0.88 0.95 RG 1 w 36 {y-175} 540 170 re B")

        flow_steps = [
            ("1. Data Ingestion:", "NVD, GHSA, CISA-KEV & Exploit-DB feeds fetch raw advisories into canonical AdvisoryRecords."),
            ("2. Local Vector Store:", "Text is chunked into 600-char windows, embedded via nomic-embed-text, & indexed in ChromaDB."),
            ("3. Scan Execution:", "CENTRIX DAST engine probes target endpoints and identifies raw vulnerability findings."),
            ("4. RAG Enrichment:", "scanner/report_generator.py passes findings to RagEngine for vector retrieval & LLM reasoning."),
            ("5. Report Generation:", "Enriched findings are output as HTML/PDF reports complete with confidence scores & warnings."),
            ("6. REST & CLI Access:", "FastAPI endpoints (/api/threat-intel/*) and centrix-intel CLI expose the intelligence pipeline."),
        ]
        y_flow = y - 15
        for step_title, step_desc in flow_steps:
            self._text(c, step_title, 46, y_flow, font="F2", size=9, color="0.01 0.52 0.78")
            self._text(c, step_desc, 150, y_flow, font="F1", size=8.5, color="0.1 0.1 0.1")
            y_flow -= 25

        y -= 200

        # Section 6: Final Conclusion
        self._text(c, "6. Conclusion & Recommendation", 36, y, font="F2", size=13, color="0.06 0.09 0.16")
        y -= 16
        txt_conc = (
            "By choosing Retrieval-Augmented Generation over Model Fine-Tuning and External Dataset Training, CENTRIX delivers "
            "an ML-powered vulnerability intelligence engine that is real-time adaptable, mathematically auditable, 100% private, "
            "and compute-efficient. This architecture ensures security auditors receive state-of-the-art AI insights backed by "
            "verifiable threat advisories without the operational overhead, latency, and hallucination risks of traditional fine-tuning."
        )
        self._draw_wrapped(c, txt_conc, 36, y, font="F1", size=9, leading=13, width=540, color="0.2 0.25 0.33")

        # Footer
        c.append("0.5 0.5 0.5 RG 0.5 w 36 30 m 576 30 l S")
        self._text(c, "CENTRIX Security Framework - ML Threat Intelligence Architecture Whitepaper", 36, 18, font="F1", size=8, color="0.4 0.4 0.4")
        self._text(c, "Page 3 of 3", 535, 18, font="F1", size=8, color="0.4 0.4 0.4")

        return "\n".join(c)

def main():
    builder = PDFBuilder()
    builder.build("CENTRIX_ML_Integration_Architecture.pdf")

if __name__ == "__main__":
    main()
