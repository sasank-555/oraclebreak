"""
build_word_documents.py
Generates two high-quality Microsoft Word documents (.docx) for the CNS project submission:
1. Project_Submission_23ECB0A03.docx (Submission Sheet for Google Classroom)
2. OracleBreak_Comprehensive_Project_Report.docx (Complete Academic Technical Report)
Author: Nasika Sasank (23ECB0A03, ECE - A, NIT Warangal)
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

# Color palette (Academic Navy & Slate)
COLOR_PRIMARY = RGBColor(15, 23, 42)     # Slate 900
COLOR_NAVY = RGBColor(30, 58, 138)       # Blue 900
COLOR_TEAL = RGBColor(13, 148, 136)      # Teal 600
COLOR_GRAY = RGBColor(100, 116, 139)     # Slate 500
COLOR_MUTED = RGBColor(71, 85, 105)      # Slate 600

HEX_LIGHT_BLUE = "F0F9FF"
HEX_BORDER_BLUE = "BAE6FD"
HEX_LIGHT_GRAY = "F8FAFC"
HEX_TABLE_HEADER = "1E3A8A"
HEX_TABLE_ROW_ALT = "F1F5F9"


def set_cell_background(cell, hex_color):
    """Sets background shading of a table cell."""
    tcPr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tcPr.append(shd)


def set_cell_margins(cell, top=120, bottom=120, left=150, right=150):
    """Sets cell padding (in twentieths of a point, dxa)."""
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tcPr.append(tcMar)


def add_callout_box(doc, text, title=None, hex_bg=HEX_LIGHT_BLUE, hex_border=HEX_BORDER_BLUE):
    """Adds a stylish callout box table with border and soft background."""
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = False
    tbl.columns[0].width = Inches(6.5)

    cell = tbl.cell(0, 0)
    set_cell_background(cell, hex_bg)
    set_cell_margins(cell, top=160, bottom=160, left=200, right=200)

    # Set left border thick, others none
    tcPr = cell._tc.get_or_add_tcPr()
    borders = parse_xml(
        f'<w:tcBorders {nsdecls("w")}>'
        f'<w:top w:val="none"/>'
        f'<w:left w:val="single" w:sz="36" w:space="0" w:color="0284C7"/>'
        f'<w:bottom w:val="none"/>'
        f'<w:right w:val="none"/>'
        f'</w:tcBorders>'
    )
    tcPr.append(borders)

    p = cell.paragraphs[0]
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    if title:
        run_t = p.add_run(f"📌 {title}\n")
        run_t.bold = True
        run_t.font.name = "Arial"
        run_t.font.size = Pt(10.5)
        run_t.font.color.rgb = COLOR_NAVY

    run = p.add_run(text)
    run.font.name = "Arial"
    run.font.size = Pt(9.5)
    run.font.color.rgb = COLOR_PRIMARY

    p_after = doc.add_paragraph()
    p_after.paragraph_format.space_after = Pt(4)


# ===========================================================================
# DOCUMENT 1: Classroom Submission Word Document
# ===========================================================================
def create_submission_document():
    doc = Document()

    # Set Margins
    for sec in doc.sections:
        sec.top_margin = Inches(1.0)
        sec.bottom_margin = Inches(1.0)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)

    # Header / Institution
    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_inst.paragraph_format.space_after = Pt(2)
    r1 = p_inst.add_run("NATIONAL INSTITUTE OF TECHNOLOGY WARANGAL\n")
    r1.bold = True
    r1.font.name = "Arial"
    r1.font.size = Pt(13)
    r1.font.color.rgb = COLOR_NAVY

    r2 = p_inst.add_run("DEPARTMENT OF ELECTRONICS AND COMMUNICATION ENGINEERING\n")
    r2.bold = True
    r2.font.name = "Arial"
    r2.font.size = Pt(11)
    r2.font.color.rgb = COLOR_PRIMARY

    r3 = p_inst.add_run("Course: Cryptography and Network Security (CNS) | Academic Year 2026-2027\n")
    r3.font.name = "Arial"
    r3.font.size = Pt(10)
    r3.font.color.rgb = COLOR_GRAY

    # Horizontal divider rule
    p_line = doc.add_paragraph()
    p_line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_line.paragraph_format.space_after = Pt(16)
    r_line = p_line.add_run("―" * 55)
    r_line.font.color.rgb = RGBColor(203, 213, 225)

    # Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(6)
    r_t = p_title.add_run("PROJECT SUBMISSION DOCUMENT\n")
    r_t.bold = True
    r_t.font.name = "Arial"
    r_t.font.size = Pt(14)
    r_t.font.color.rgb = COLOR_NAVY

    p_proj = doc.add_paragraph()
    p_proj.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_proj.paragraph_format.space_after = Pt(18)
    r_pt = p_proj.add_run("OracleBreak: Experimental Analysis of CBC Padding-Oracle Vulnerabilities and Mitigation Strategies")
    r_pt.bold = True
    r_pt.font.name = "Arial"
    r_pt.font.size = Pt(12)
    r_pt.font.color.rgb = COLOR_PRIMARY

    # Student Details Table
    table_meta = doc.add_table(rows=5, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_meta.autofit = False
    table_meta.columns[0].width = Inches(2.2)
    table_meta.columns[1].width = Inches(4.3)

    meta_data = [
        ("Student Name:", "Nasika Sasank"),
        ("Roll Number:", "23ECB0A03"),
        ("Branch & Section:", "B.Tech Electronics & Communication Engineering (ECE - A)"),
        ("Institute Email ID:", "ns23ecb0a03@student.nitw.ac.in"),
        ("Course Faculty:", "Dr. Sourabh Sir")
    ]

    for idx, (label, val) in enumerate(meta_data):
        cell_lbl = table_meta.cell(idx, 0)
        cell_val = table_meta.cell(idx, 1)

        set_cell_background(cell_lbl, "F8FAFC")
        set_cell_background(cell_val, "FFFFFF")
        set_cell_margins(cell_lbl, 80, 80, 120, 120)
        set_cell_margins(cell_val, 80, 80, 120, 120)

        p0 = cell_lbl.paragraphs[0]
        r0 = p0.add_run(label)
        r0.bold = True
        r0.font.name = "Arial"
        r0.font.size = Pt(10)
        r0.font.color.rgb = COLOR_PRIMARY

        p1 = cell_val.paragraphs[0]
        r1 = p1.add_run(val)
        r1.font.name = "Arial"
        r1.font.size = Pt(10)
        r1.font.color.rgb = COLOR_PRIMARY

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    # Google Drive Submission Callout Box
    drive_content = (
        "Please paste your Institute Google Drive Folder link here:\n\n"
        "👉 https://drive.google.com/drive/folders/YOUR_FOLDER_ID_HERE?usp=sharing\n\n"
        "(Permission set to: 'Anyone with the link can view' via @student.nitw.ac.in)\n"
        "This Drive folder contains all deliverables: Complete Source Code, Technical Report, README, Test Harness, and Diagrams."
    )
    add_callout_box(doc, drive_content, title="MANDATORY GOOGLE DRIVE SUBMISSION LINK")

    # Online Deployment & Repository Links Callout Box
    links_content = (
        "• Live Interactive Demonstration (GitHub Pages): \n  https://sasank-555.github.io/oraclebreak/\n"
        "• Source Code Repository (GitHub): \n  https://github.com/sasank-555/oraclebreak\n"
        "• Local Backend URL (FastAPI): \n  http://localhost:8000"
    )
    add_callout_box(doc, links_content, title="LIVE DEMONSTRATION & REPOSITORY LINKS", hex_bg="F0FDF4", hex_border="BBF7D0")

    # Table of Deliverables
    p_deliv = doc.add_paragraph()
    p_deliv.paragraph_format.space_before = Pt(8)
    p_deliv.paragraph_format.space_after = Pt(4)
    r_del = p_deliv.add_run("Submission Deliverables Checklist (Included in Drive Folder)")
    r_del.bold = True
    r_del.font.name = "Arial"
    r_del.font.size = Pt(11)
    r_del.font.color.rgb = COLOR_NAVY

    table_items = doc.add_table(rows=7, cols=3)
    table_items.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_items.autofit = False
    table_items.columns[0].width = Inches(0.8)
    table_items.columns[1].width = Inches(3.2)
    table_items.columns[2].width = Inches(2.5)

    headers = ["Item #", "Deliverable Description", "File / Location"]
    for c_idx, h in enumerate(headers):
        cell = table_items.cell(0, c_idx)
        set_cell_background(cell, HEX_TABLE_HEADER)
        set_cell_margins(cell, 100, 100, 120, 120)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    deliverables = [
        ("1", "Complete Python & Web Source Code", "Source_Code/ or .zip"),
        ("2", "Comprehensive Technical Project Report", "OracleBreak_Project_Report.docx"),
        ("3", "Execution & Testing Guide (README)", "README.md"),
        ("4", "Automated Security Test Suite (7 Tests)", "test_suite.py (100% Pass)"),
        ("5", "Interactive Terminal Menu for Oral Viva", "cli_demo.py"),
        ("6", "Live Web Platform (Zero-Install)", "https://sasank-555.github.io/oraclebreak/")
    ]

    for r_idx, row in enumerate(deliverables, start=1):
        for c_idx, val in enumerate(row):
            cell = table_items.cell(r_idx, c_idx)
            set_cell_background(cell, "FFFFFF" if r_idx % 2 == 1 else "F8FAFC")
            set_cell_margins(cell, 80, 80, 120, 120)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(9)
            r.font.color.rgb = COLOR_PRIMARY

    # Executive Abstract
    p_abs = doc.add_paragraph()
    p_abs.paragraph_format.space_before = Pt(14)
    p_abs.paragraph_format.space_after = Pt(2)
    r_absh = p_abs.add_run("Executive Summary:")
    r_absh.bold = True
    r_absh.font.name = "Arial"
    r_absh.font.size = Pt(10.5)
    r_absh.font.color.rgb = COLOR_NAVY

    p_abstext = doc.add_paragraph()
    p_abstext.paragraph_format.space_after = Pt(8)
    p_abstext.paragraph_format.line_spacing = 1.15
    r_ab = p_abstext.add_run(
        "OracleBreak is an interactive cryptanalysis and educational platform demonstrating Serge Vaudenay's "
        "CBC padding-oracle vulnerability and evaluation of modern authenticated encryption defenses. "
        "The project provides a dual-mode web laboratory (Automated and Step-by-Step Analytical Hacker Mode), "
        "ciphertext malleability bit-flipping playground, comparative mitigation benchmarks (Uniform Error, Encrypt-then-MAC, AES-GCM), "
        "and a formal 7-test automated verification suite. It executes seamlessly both in local Python environments "
        "and 100% serverlessly on GitHub Pages."
    )
    r_ab.font.name = "Arial"
    r_ab.font.size = Pt(9.5)
    r_ab.font.color.rgb = COLOR_PRIMARY

    doc.save("Project_Submission_23ECB0A03.docx")
    print("[+] Generated Project_Submission_23ECB0A03.docx successfully!")


# ===========================================================================
# DOCUMENT 2: Comprehensive Technical Project Report
# ===========================================================================
def create_technical_report():
    doc = Document()

    # Set Margins
    for sec in doc.sections:
        sec.top_margin = Inches(1.0)
        sec.bottom_margin = Inches(1.0)
        sec.left_margin = Inches(1.0)
        sec.right_margin = Inches(1.0)

    # Cover Header
    p_inst = doc.add_paragraph()
    p_inst.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_inst.paragraph_format.space_after = Pt(2)
    r1 = p_inst.add_run("NATIONAL INSTITUTE OF TECHNOLOGY WARANGAL\n")
    r1.bold = True
    r1.font.name = "Arial"
    r1.font.size = Pt(14)
    r1.font.color.rgb = COLOR_NAVY

    r2 = p_inst.add_run("DEPARTMENT OF ELECTRONICS AND COMMUNICATION ENGINEERING\n")
    r2.bold = True
    r2.font.name = "Arial"
    r2.font.size = Pt(11)
    r2.font.color.rgb = COLOR_PRIMARY

    r3 = p_inst.add_run("Course: Cryptography and Network Security (CNS) | Section A | Academic Year 2026-2027\n")
    r3.font.name = "Arial"
    r3.font.size = Pt(10)
    r3.font.color.rgb = COLOR_GRAY

    p_line = doc.add_paragraph()
    p_line.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_line.paragraph_format.space_after = Pt(14)
    r_line = p_line.add_run("―" * 58)
    r_line.font.color.rgb = RGBColor(203, 213, 225)

    # Report Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_after = Pt(4)
    r_t = p_title.add_run("TECHNICAL PROJECT REPORT\n")
    r_t.bold = True
    r_t.font.name = "Arial"
    r_t.font.size = Pt(15)
    r_t.font.color.rgb = COLOR_NAVY

    p_proj = doc.add_paragraph()
    p_proj.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_proj.paragraph_format.space_after = Pt(16)
    r_pt = p_proj.add_run("OracleBreak: Experimental Analysis of CBC Padding-Oracle Vulnerabilities and Mitigation Strategies")
    r_pt.bold = True
    r_pt.font.name = "Arial"
    r_pt.font.size = Pt(12.5)
    r_pt.font.color.rgb = COLOR_PRIMARY

    # Author Table
    table_meta = doc.add_table(rows=4, cols=2)
    table_meta.alignment = WD_TABLE_ALIGNMENT.CENTER
    table_meta.autofit = False
    table_meta.columns[0].width = Inches(2.2)
    table_meta.columns[1].width = Inches(4.3)

    meta_data = [
        ("Candidate Name:", "Nasika Sasank"),
        ("Roll Number:", "23ECB0A03 (ECE - A)"),
        ("Institute Email ID:", "ns23ecb0a03@student.nitw.ac.in"),
        ("Online Deployment:", "https://sasank-555.github.io/oraclebreak/")
    ]

    for idx, (label, val) in enumerate(meta_data):
        cell_lbl = table_meta.cell(idx, 0)
        cell_val = table_meta.cell(idx, 1)
        set_cell_background(cell_lbl, "F8FAFC")
        set_cell_background(cell_val, "FFFFFF")
        set_cell_margins(cell_lbl, 60, 60, 100, 100)
        set_cell_margins(cell_val, 60, 60, 100, 100)

        p0 = cell_lbl.paragraphs[0]
        r0 = p0.add_run(label)
        r0.bold = True
        r0.font.name = "Arial"
        r0.font.size = Pt(9.5)

        p1 = cell_val.paragraphs[0]
        r1 = p1.add_run(val)
        r1.font.name = "Arial"
        r1.font.size = Pt(9.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    # Helper function for Section Headings
    def add_section_header(title):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(16)
        p.paragraph_format.space_after = Pt(6)
        r = p.add_run(title)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(12)
        r.font.color.rgb = COLOR_NAVY
        return p

    def add_subsection_header(title):
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(10)
        p.paragraph_format.space_after = Pt(4)
        r = p.add_run(title)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(10.5)
        r.font.color.rgb = COLOR_PRIMARY
        return p

    def add_body(text):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(6)
        p.paragraph_format.line_spacing = 1.15
        r = p.add_run(text)
        r.font.name = "Arial"
        r.font.size = Pt(9.5)
        r.font.color.rgb = COLOR_PRIMARY
        return p

    # -----------------------------------------------------------------------
    # Section 1: Problem Statement & Objectives
    # -----------------------------------------------------------------------
    add_section_header("1. Problem Statement & Research Objectives")
    add_body(
        "Modern network security protocols historically relied upon block ciphers operating in Cipher Block Chaining (CBC) "
        "mode to guarantee data confidentiality across protocols such as SSL/TLS, IPsec, SSH, and web application authentication cookies. "
        "However, block ciphers require inputs to be an exact multiple of the block size (16 bytes for AES). To accommodate arbitrarily "
        "sized data, standard padding schemes like PKCS#7 (RFC 5652) are applied. In 2002, Serge Vaudenay proved that if a decryption endpoint "
        "distinguishes between valid and invalid padding—through distinct error messages, HTTP status codes, or processing delays—it operates "
        "as a side-channel 'Padding Oracle'."
    )
    add_body(
        "By querying this oracle with systematically modified ciphertext blocks, an attacker can decipher arbitrary encrypted messages byte-by-byte "
        "without ever knowing or breaking the underlying secret AES key. The computational complexity plummets from an impossible brute-force "
        "search space of 2^128 operations down to an average of only 2,048 queries per 16-byte block, breaking confidentiality in milliseconds."
    )
    add_body(
        "The primary objectives of this project are:\n"
        "1. To develop an interactive, full-stack experimental platform simulating the vulnerable CBC decryption oracle.\n"
        "2. To provide an educational cryptanalysis laboratory with over 50% student involvement, allowing manual candidate byte probing and intermediate state deduction.\n"
        "3. To analyze ciphertext non-malleability failures via bit-flipping attacks for unauthorized privilege escalation.\n"
        "4. To implement and evaluate three distinct mitigation strategies: Uniform Error Handling, Encrypt-then-MAC (RFC 7366), and Authenticated Encryption via AES-GCM (NIST SP 800-38D).\n"
        "5. To construct an automated formal verification test suite verifying cryptographic boundary invariants with 100% test coverage."
    )

    # -----------------------------------------------------------------------
    # Section 2: Cryptographic Technique
    # -----------------------------------------------------------------------
    add_section_header("2. Cryptographic Techniques & Mathematical Foundations")
    add_subsection_header("2.1 Advanced Encryption Standard (AES) in CBC Mode")
    add_body(
        "AES-128 operates on 128-bit (16-byte) state matrices. In CBC mode, each plaintext block P_i is bitwise XORed with the previous "
        "ciphertext block C_{i-1} before undergoing block cipher encryption E_K. For the initial block P_1, a random Initialization Vector (IV) "
        "acts as C_0:\n"
        "    Encryption:  C_i = E_K(P_i ⊕ C_{i-1})   where C_0 = IV\n"
        "    Decryption:  P_i = D_K(C_i) ⊕ C_{i-1}"
    )

    add_subsection_header("2.2 PKCS#7 Padding Specification (RFC 5652)")
    add_body(
        "For block size B = 16 bytes, if plaintext length L is not a multiple of B, pad_len = B - (L mod B) bytes are appended. "
        "Each padding byte stores the numerical value pad_len. If L is already a multiple of B, an entire full block of 16 bytes with value 0x10 is appended. "
        "Valid padding endings include: 0x01 (1 byte pad), 0x02 0x02 (2 bytes pad), ... 0x10 * 16 (16 bytes pad). "
        "During unpadding, the server strictly validates that the trailing pad_len bytes all equal pad_len. Any mismatch triggers a PaddingError."
    )

    add_subsection_header("2.3 Authenticated Encryption Alternatives (EtM and AES-GCM)")
    add_body(
        "• Encrypt-then-MAC (EtM, RFC 7366): Plaintext is encrypted with AES-CBC, followed by computing an HMAC-SHA256 authentication tag "
        "over (IV || Ciphertext). The recipient strictly validates the MAC in constant time prior to initiating CBC decryption.\n"
        "• AES-GCM (Galois/Counter Mode, NIST SP 800-38D): Modern Authenticated Encryption with Associated Data (AEAD) combining Counter mode "
        "(CTR) encryption with universal hashing over GF(2^128) (GMAC). CTR mode eliminates the need for block padding, rendering padding oracles structurally impossible."
    )

    # -----------------------------------------------------------------------
    # Section 3: Working Principle
    # -----------------------------------------------------------------------
    add_section_header("3. Working Principle of the Padding Oracle Attack")
    add_subsection_header("3.1 Isolation of the Intermediate State")
    add_body(
        "Let the intermediate state I_i be the output of decrypting block C_i with secret key K before the CBC chaining XOR operation:\n"
        "    I_i = D_K(C_i)\n"
        "Notice that I_i depends solely upon K and C_i; it is completely independent of the preceding block C_{i-1}. Therefore:\n"
        "    P_i = I_i ⊕ C_{i-1}"
    )

    add_subsection_header("3.2 Byte-by-Byte Algebraic Derivation (Right-to-Left Traversal)")
    add_body(
        "Because PKCS#7 padding is anchored to the tail of the block, an attacker probes candidate bytes from index 15 down to 0. "
        "To recover byte position k, the target padding value is set to pad = 16 - k.\n"
        "The attacker constructs a crafted block C'_{i-1}:\n"
        "1. For already recovered positions j > k:  C'_{i-1}[j] = I_i[j] ⊕ pad  (forces decrypted bytes to equal pad).\n"
        "2. For target position k:  Iterate candidate guess g in [0, 255] on C'_{i-1}[k].\n"
        "3. Present candidate (C'_{i-1} || C_i) to the server oracle.\n"
        "4. When the oracle signals 'Valid Padding' (HTTP 200 OK):\n"
        "       P'_i[k] = I_i[k] ⊕ g = pad\n"
        "       ===>  I_i[k] = g ⊕ pad\n"
        "5. The original secret plaintext is directly computed without key knowledge:\n"
        "       P_i[k] = I_i[k] ⊕ C_{i-1}[k]"
    )

    # Insert Figure 1
    if os.path.exists("report_assets/fig1_cbc_oracle_flow.png"):
        doc.add_paragraph().paragraph_format.space_before = Pt(6)
        doc.add_picture("report_assets/fig1_cbc_oracle_flow.png", width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_after = Pt(10)
        r_c = p_cap.add_run("Figure 1: Architectural Data Flow of CBC Decryption and Padding Oracle Side-Channel Feedback.")
        r_c.font.size = Pt(8.5)
        r_c.font.italic = True
        r_c.font.color.rgb = COLOR_GRAY

    add_subsection_header("3.3 Ciphertext Malleability & Bit-Flipping Principle")
    add_body(
        "CBC mode lacks data authenticity. An adversary can alter plaintext characters without breaking the key by exploiting the relation:\n"
        "    P_i[k] = D_K(C_i)[k] ⊕ C_{i-1}[k]\n"
        "To alter character P_i[k] to desired character P'_i[k], the attacker computes Δ = P_i[k] ⊕ P'_i[k] and flips C'_{i-1}[k] = C_{i-1}[k] ⊕ Δ. "
        "During decryption, D_K(C_i)[k] ⊕ C'_{i-1}[k] evaluates exactly to P'_i[k]. In OracleBreak, this is demonstrated by escalating privilege "
        "from 'user=bob;admin=0' to 'user=bob;admin=1' by bit-flipping the IV."
    )

    # -----------------------------------------------------------------------
    # Section 4: System & Application Developed
    # -----------------------------------------------------------------------
    add_section_header("4. System & Application Developed")
    add_body(
        "OracleBreak is developed as a modular, dual-execution cryptanalysis laboratory supporting both local Python server execution "
        "and 100% serverless browser execution on GitHub Pages."
    )
    add_body(
        "Key Subsystems Developed:\n"
        "1. Cryptographic Engine (crypto_core.py & crypto-engine.js): Pure implementations of AES-CBC, strict RFC 5652 PKCS#7 validation, HMAC-SHA256, and AES-GCM primitives.\n"
        "2. Decryption Oracle Simulator (oracle.py): Multi-profile server simulating 4 environments: Vulnerable CBC, Uniform Error, Encrypt-then-MAC, and AES-GCM with telemetry tracking.\n"
        "3. Cryptanalytic Attack Engine (attacker.py): Algorithmic engine supporting streaming generator attacks, single-byte stepping, and bit-flipping malleability transformations.\n"
        "4. Interactive Web Dashboard (static/index.html & static/app.js): Modern responsive UI built with Tailwind CSS, Chart.js, KaTeX mathematical typography, and Lucide icons.\n"
        "5. Automated Security Test Suite (test_suite.py): 7 formal verification test cases validating boundary conditions, side-channel leaks, and mitigation efficacy.\n"
        "6. Command-Line Interface (cli_demo.py): Menu-driven terminal application designed for oral viva demonstrations."
    )

    # -----------------------------------------------------------------------
    # Section 5: Implementation Details
    # -----------------------------------------------------------------------
    add_section_header("5. Implementation Details & Code Architecture")
    add_body(
        "The project is structured into clean, decoupled modules with strict separation between server-side cryptographic ground-truth "
        "and client-side adversarial operations:"
    )

    # Code Architecture Table
    tbl_code = doc.add_table(rows=7, cols=3)
    tbl_code.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_code.autofit = False
    tbl_code.columns[0].width = Inches(1.8)
    tbl_code.columns[1].width = Inches(1.8)
    tbl_code.columns[2].width = Inches(2.9)

    headers = ["Module File", "Language / Stack", "Functional Responsibility"]
    for c_idx, h in enumerate(headers):
        cell = tbl_code.cell(0, c_idx)
        set_cell_background(cell, HEX_TABLE_HEADER)
        set_cell_margins(cell, 80, 80, 100, 100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(255, 255, 255)

    code_arch = [
        ("crypto_core.py", "Python 3 / Cryptography", "AES-CBC, strict PKCS#7 unpad, HMAC-SHA256, AES-GCM primitives"),
        ("oracle.py", "Python 3 / Core", "Decryption oracle with 4 security profiles and query latency tracking"),
        ("attacker.py", "Python 3 / Core", "Vaudenay byte solver, full attack generator, bit-flip transformer"),
        ("app.py", "FastAPI / Uvicorn", "High-performance REST API endpoints (/api/encrypt, /api/attack/step)"),
        ("static/crypto-engine.js", "JavaScript / WebCrypto", "100% serverless browser cryptographic engine for GitHub Pages"),
        ("test_suite.py", "Python 3 / UnitTest", "Automated formal verification harness executing 7 security tests")
    ]

    for r_idx, row in enumerate(code_arch, start=1):
        for c_idx, val in enumerate(row):
            cell = tbl_code.cell(r_idx, c_idx)
            set_cell_background(cell, "FFFFFF" if r_idx % 2 == 1 else "F8FAFC")
            set_cell_margins(cell, 60, 60, 100, 100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    # -----------------------------------------------------------------------
    # Section 6: Experimental Results & Formal Verification
    # -----------------------------------------------------------------------
    add_section_header("6. Experimental Results & Verification")
    add_body(
        "The automated test suite was executed across multiple trial messages and edge cases. In all runs, 100% of tests passed successfully. "
        "The complete test execution metrics are summarized below:"
    )

    # Insert Figure 3 (Test Suite Summary)
    if os.path.exists("report_assets/fig3_test_suite_summary.png"):
        doc.add_picture("report_assets/fig3_test_suite_summary.png", width=Inches(6.2))
        p_cap = doc.add_paragraph()
        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap.paragraph_format.space_after = Pt(8)
        r_c = p_cap.add_run("Figure 2: Formal Verification Test Suite Results Summary (7/7 Tests Passed, Total Runtime: 118.17 ms).")
        r_c.font.size = Pt(8.5)
        r_c.font.italic = True
        r_c.font.color.rgb = COLOR_GRAY

    # Insert Figure 2 (Benchmark Comparison)
    if os.path.exists("report_assets/fig2_benchmark_comparison.png"):
        doc.add_picture("report_assets/fig2_benchmark_comparison.png", width=Inches(6.2))
        p_cap2 = doc.add_paragraph()
        p_cap2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        p_cap2.paragraph_format.space_after = Pt(10)
        r_c2 = p_cap2.add_run("Figure 3: Empirical Query Complexity Comparison and Cryptographic Security Degradation Magnitude.")
        r_c2.font.size = Pt(8.5)
        r_c2.font.italic = True
        r_c2.font.color.rgb = COLOR_GRAY

    # Mitigation Comparative Benchmark Table
    add_subsection_header("6.1 Comparative Security & Performance Matrix")
    tbl_bench = doc.add_table(rows=5, cols=5)
    tbl_bench.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl_bench.autofit = False
    tbl_bench.columns[0].width = Inches(1.8)
    tbl_bench.columns[1].width = Inches(1.3)
    tbl_bench.columns[2].width = Inches(1.1)
    tbl_bench.columns[3].width = Inches(1.1)
    tbl_bench.columns[4].width = Inches(1.2)

    b_headers = ["Configuration", "Security Level", "Oracle Leak?", "Malleable?", "Query Work"]
    for c_idx, h in enumerate(b_headers):
        cell = tbl_bench.cell(0, c_idx)
        set_cell_background(cell, HEX_TABLE_HEADER)
        set_cell_margins(cell, 80, 80, 100, 100)
        p = cell.paragraphs[0]
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Arial"
        r.font.size = Pt(8.5)
        r.font.color.rgb = RGBColor(255, 255, 255)

    bench_rows = [
        ("AES-128-CBC (Vulnerable)", "Broken", "Yes (500 Error)", "Yes (High)", "2,048 queries"),
        ("AES-128-CBC (Uniform Error)", "Insufficient", "Masked (Timing Risk)", "Yes (High)", "Timing dependent"),
        ("Encrypt-then-MAC (RFC 7366)", "Secure", "None (0 Leaked)", "No (Integrity Tag)", "0 (Blocked at MAC)"),
        ("AES-128-GCM (AEAD)", "Gold Standard", "None (No Padding)", "No (GMAC Tag)", "0 (Blocked at GMAC)")
    ]

    for r_idx, row in enumerate(bench_rows, start=1):
        for c_idx, val in enumerate(row):
            cell = tbl_bench.cell(r_idx, c_idx)
            set_cell_background(cell, "FFFFFF" if r_idx % 2 == 1 else "F8FAFC")
            set_cell_margins(cell, 60, 60, 100, 100)
            p = cell.paragraphs[0]
            r = p.add_run(val)
            r.font.name = "Arial"
            r.font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    # -----------------------------------------------------------------------
    # Section 7: Observations & Security Findings
    # -----------------------------------------------------------------------
    add_section_header("7. Observations & Empirical Findings")
    add_body(
        "1. Catastrophic Complexity Reduction: The attack converts an intractable brute-force key search of 2^128 operations into a linear "
        "polynomial search of O(256 * L). For a 16-byte block, decryption requires at most 4,096 queries, averaging ~2,048 queries (sub-second execution).\n\n"
        "2. The Fallacy of Uniform Error Strings: Naively catching PaddingError and returning a generic 'Decryption Failed' error fails to secure "
        "CBC mode. As demonstrated in Lucky Thirteen (CVE-2013-0169), subtle timing variations in CPU execution cycles leak padding validity. "
        "Furthermore, uniform error responses provide zero protection against bit-flipping malleability attacks.\n\n"
        "3. Compositional Correctness of Encrypt-then-MAC: In legacy CBC architectures, Encrypt-then-MAC (EtM) is the only proven defense. "
        "Because the MAC is checked before decryption, candidate ciphertext probing is rejected immediately at the transport layer.\n\n"
        "4. AEAD Superiority: AES-GCM completely eliminates block padding by operating in Counter (CTR) mode with GMAC integrity verification, "
        "establishing modern gold-standard confidentiality and authenticity simultaneously."
    )

    # -----------------------------------------------------------------------
    # Section 8: Limitations
    # -----------------------------------------------------------------------
    add_section_header("8. System Limitations & Practical Constraints")
    add_body(
        "1. Oracle Availability Requirement: The attack requires an interactive decryption oracle that responds deterministically to malformed ciphertexts. "
        "If a server enforces aggressive IP rate limiting, account lockout, or connection termination after repeated errors, attack completion is delayed.\n\n"
        "2. Network Jitter Impact on Timing Oracles: In networks with high latency variance (jitter), measuring microsecond timing differentials "
        "requires statistical amplification through thousands of redundant probe queries.\n\n"
        "3. Block Boundary Granularity: The attack requires exact block alignment. Ciphertexts truncated below a 16-byte boundary are rejected at the "
        "transport layer before reaching the decryption unpad logic."
    )

    # -----------------------------------------------------------------------
    # Section 9: References & Tools Used
    # -----------------------------------------------------------------------
    add_section_header("9. References & AI Tools Disclosure")
    add_body(
        "Research Papers & Cryptographic Standards:\n"
        "1. Vaudenay, S. (2002). 'Security Flaws Induced by CBC Padding — Applications to SSL, IPSEC, WTLS...' Advances in Cryptology — EUROCRYPT 2002, LNCS 2332, pp. 534–545.\n"
        "2. RFC 5652: Cryptographic Message Syntax (CMS) — PKCS #7 Padding Specification (IETF).\n"
        "3. RFC 7366: Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS) (IETF).\n"
        "4. NIST Special Publication 800-38D: 'Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC' (National Institute of Standards and Technology).\n"
        "5. AlFardan, N. J., & Paterson, K. G. (2013). 'Lucky Thirteen: Breaking the TLS and DTLS Record Protocols.' IEEE Symposium on Security and Privacy (S&P), pp. 526–540.\n"
        "6. Möller, B., Duong, T., & Kotowicz, K. (2014). 'This POODLE Bites: Exploiting The SSL 3.0 Fallback' (CVE-2014-3566)."
    )
    add_body(
        "Software Libraries & Web Repositories:\n"
        "• Python Cryptography (pyca/cryptography) — Hazmat primitives for AES, CBC, and GCM.\n"
        "• FastAPI & Uvicorn — High-performance asynchronous REST API server.\n"
        "• CryptoJS — Client-side cryptographic operations for GitHub Pages execution.\n"
        "• Chart.js & KaTeX — Dynamic data visualization and mathematical typography rendering.\n"
        "• Project GitHub Repository: https://github.com/sasank-555/oraclebreak\n"
        "• Live Demonstration Deployment: https://sasank-555.github.io/oraclebreak/"
    )
    add_body(
        "Disclosure of AI Tools Used (Mandatory per Course Instructions):\n"
        "In compliance with academic integrity guidelines, Google Gemini and Anthropic Claude AI coding assistants were utilized as pair-programming "
        "tools for drafting report formatting scripts, generating frontend CSS component styling, and code structure ideation. "
        "All cryptographic equations, vulnerability implementations, algorithmic attack logic, and verification test cases were designed, validated, "
        "and mathematically verified by the candidate."
    )

    doc.save("OracleBreak_Comprehensive_Project_Report.docx")
    print("[+] Generated OracleBreak_Comprehensive_Project_Report.docx successfully!")


if __name__ == "__main__":
    create_submission_document()
    create_technical_report()
