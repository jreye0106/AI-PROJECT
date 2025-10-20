"""
AI Generator GUI — PySide6

This GUI implements the structure described in the project guide:
- Tabs: Code Generation, Vulnerability Detection, Summarization
- Input collection & validation
- Engine selection & execution pipeline with stubs
- Output panels and save/export (TXT/MD/PDF)
- Error handling & developer-friendly feedback
- Clear seam points for integrating real engines later

Run:
  pip install PySide6
  python ai_generator_gui.py
"""
from __future__ import annotations

import sys
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from PySide6 import QtCore, QtGui, QtWidgets


# ------------------------------
# Engine Interfaces (Stubs)
# ------------------------------
class Engine(Protocol):
    """Abstract interface for all engines.
    Real implementations should replace `process` bodies.
    """

    def process(self, data: str) -> str:
        ...


class CodeGenerationEngine:
    """Stub for code generation (e.g., CodeT5/DeepSeek-coder etc.)."""
    def process(self, data: str) -> str:
        # TODO: replace with real model call
        return (
            "# Generated code (stub)\n"
            "# Prompt:\n" + data + "\n\n"
            "def hello():\n    print('Hello from the generated code stub!')\n"
        )


class VulnerabilityDetectionEngine:
    """Stub for vulnerability scanning (e.g., CodeBERT fine-tuned)."""
    def process(self, data: str) -> str:
        # TODO: replace with real vuln detection; return JSON or structured text
        fake_report = {
            "summary": "Static heuristic scan complete (stub)",
            "issues": [
                {"id": "VULN-001", "title": "Potential SQL Injection", "severity": "HIGH", "line": 42},
                {"id": "VULN-002", "title": "Hardcoded secret detected", "severity": "CRITICAL", "line": 7},
                {"id": "VULN-003", "title": "Weak cryptography (MD5)", "severity": "MEDIUM", "line": 128},
            ],
        }
        return json.dumps(fake_report, indent=2)


class SummarizationEngine:
    """Stub for code/text summarization."""
    def process(self, data: str) -> str:
        # TODO: replace with real summarization call
        return (
            "Summary (stub): This content appears to define functions/classes. "
            "Key responsibilities are identified and described succinctly."
        )


# ------------------------------
# System/Controller
# ------------------------------
@dataclass
class ValidationResult:
    ok: bool
    message: str = ""


class GeneratorSystem(QtCore.QObject):
    """Coordinates input validation, engine execution, and output display."""

    outputReady = QtCore.Signal(str)
    errorOccurred = QtCore.Signal(str)

    def __init__(self, parent: Optional[QtCore.QObject] = None) -> None:
        super().__init__(parent)
        self._engines: dict[str, Engine] = {
            "code_generation": CodeGenerationEngine(),
            "vulnerability_detection": VulnerabilityDetectionEngine(),
            "summarization": SummarizationEngine(),
        }

    # ---- Core Functional Needs: Prompt Input & Validation ----
    def validate_input(self, text: str) -> ValidationResult:
        if not text or not text.strip():
            return ValidationResult(False, "Input is empty. Please enter a prompt or paste code.")
        if len(text) < 3:
            return ValidationResult(False, "Input is too short. Provide more detail for better results.")
        return ValidationResult(True)

    # ---- Execute Engine ----
    def execute_engine(self, engine_key: str, text: str) -> None:
        vres = self.validate_input(text)
        if not vres.ok:
            self.errorOccurred.emit(vres.message)
            return
        engine = self._engines.get(engine_key)
        if engine is None:
            self.errorOccurred.emit(f"Unknown engine: {engine_key}")
            return
        try:
            # NOTE: Replace with async/threaded call if your real engine is slow
            result = engine.process(text)
            self.outputReady.emit(result)
        except Exception as ex:  # pragma: no cover
            self.errorOccurred.emit(f"Engine error: {ex}")


# ------------------------------
# UI Widgets
# ------------------------------
class InputPanel(QtWidgets.QWidget):
    """Shared input panel with a text editor, file loader, and run button."""

    runRequested = QtCore.Signal(str)  # emits the input text

    def __init__(self, placeholder: str, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.editor = QtWidgets.QPlainTextEdit()
        self.editor.setPlaceholderText(placeholder)
        self.editor.setMinimumHeight(160)
        self.editor.setTabChangesFocus(False)
        self.editor.setWordWrapMode(QtGui.QTextOption.NoWrap)
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.editor.setFont(font)

        self.load_btn = QtWidgets.QPushButton("Load File…")
        self.run_btn = QtWidgets.QPushButton("Run")

        btn_row = QtWidgets.QHBoxLayout()
        btn_row.addWidget(self.load_btn)
        btn_row.addStretch(1)
        btn_row.addWidget(self.run_btn)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.editor)
        layout.addLayout(btn_row)

        self.load_btn.clicked.connect(self._on_load)
        self.run_btn.clicked.connect(self._on_run)

    def _on_load(self) -> None:
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open file", str(Path.home()),
                                                        "Text/Code Files (*.txt *.py *.js *.ts *.java *.c *.cpp *.md);;All Files (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
            self.editor.setPlainText(text)
        except Exception as ex:  # pragma: no cover
            QtWidgets.QMessageBox.critical(self, "Read Error", f"Failed to read file:\n{ex}")

    def _on_run(self) -> None:
        self.runRequested.emit(self.editor.toPlainText())

    def text(self) -> str:
        return self.editor.toPlainText()


class OutputPanel(QtWidgets.QWidget):
    """Shared output panel with text display and export options."""

    def __init__(self, title: str, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.title = title

        self.output = QtWidgets.QPlainTextEdit()
        self.output.setReadOnly(True)
        font = QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont)
        self.output.setFont(font)

        self.save_btn = QtWidgets.QPushButton("Save as .txt")
        self.export_md_btn = QtWidgets.QPushButton("Export .md")
        self.export_pdf_btn = QtWidgets.QPushButton("Export .pdf")

        btns = QtWidgets.QHBoxLayout()
        btns.addWidget(self.save_btn)
        btns.addWidget(self.export_md_btn)
        btns.addWidget(self.export_pdf_btn)
        btns.addStretch(1)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.output)
        layout.addLayout(btns)

        self.save_btn.clicked.connect(lambda: self._export("txt"))
        self.export_md_btn.clicked.connect(lambda: self._export("md"))
        self.export_pdf_btn.clicked.connect(lambda: self._export_pdf())

    def set_text(self, text: str) -> None:
        self.output.setPlainText(text)

    def _export(self, ext: str) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, f"Save {self.title}", str(Path.home() / f"output.{ext}"), f"*.{ext}")
        if not path:
            return
        try:
            Path(path).write_text(self.output.toPlainText(), encoding="utf-8")
            QtWidgets.QMessageBox.information(self, "Saved", f"Saved to:\n{path}")
        except Exception as ex:  # pragma: no cover
            QtWidgets.QMessageBox.critical(self, "Save Error", f"Failed to save file:\n{ex}")

    def _export_pdf(self) -> None:
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, f"Export {self.title} as PDF", str(Path.home() / "output.pdf"), "*.pdf")
        if not path:
            return
        try:
            doc = QtGui.QTextDocument(self.output.toPlainText())
            printer = QtGui.QPdfWriter(path)
            # A4 default; adjust margins if desired
            doc.print_(printer)
            QtWidgets.QMessageBox.information(self, "Exported", f"PDF exported to:\n{path}")
        except Exception as ex:  # pragma: no cover
            QtWidgets.QMessageBox.critical(self, "Export Error", f"Failed to export PDF:\n{ex}")


class VulnTable(QtWidgets.QTableWidget):
    """Simple table to render vulnerability JSON (id, title, severity, line)."""

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(0, 4, parent)
        self.setHorizontalHeaderLabels(["ID", "Title", "Severity", "Line"])
        self.horizontalHeader().setStretchLastSection(True)
        self.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

    def load_from_json(self, text: str) -> None:
        self.setRowCount(0)
        try:
            data = json.loads(text)
            issues = data.get("issues", []) if isinstance(data, dict) else []
            for issue in issues:
                row = self.rowCount()
                self.insertRow(row)
                self.setItem(row, 0, QtWidgets.QTableWidgetItem(str(issue.get("id", ""))))
                self.setItem(row, 1, QtWidgets.QTableWidgetItem(str(issue.get("title", ""))))
                sev = str(issue.get("severity", "")).upper()
                self.setItem(row, 2, QtWidgets.QTableWidgetItem(sev))
                self.setItem(row, 3, QtWidgets.QTableWidgetItem(str(issue.get("line", ""))))
                # Simple severity coloring
                if sev in {"CRITICAL", "HIGH"}:
                    self.item(row, 2).setForeground(QtGui.QBrush(QtGui.QColor("red")))
                elif sev == "MEDIUM":
                    self.item(row, 2).setForeground(QtGui.QBrush(QtGui.QColor("darkorange")))
                elif sev == "LOW":
                    self.item(row, 2).setForeground(QtGui.QBrush(QtGui.QColor("green")))
        except Exception:
            # Not JSON; ignore silently — panel still shows raw text in OutputPanel
            pass


# ------------------------------
# Pages / Tabs
# ------------------------------
class CodeGenPage(QtWidgets.QWidget):
    def __init__(self, system: GeneratorSystem, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.system = system
        self.input_panel = InputPanel("Describe the program or function you want…")
        self.output_panel = OutputPanel("Generated Code")

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.input_panel)
        layout.addWidget(self.output_panel)

        self.input_panel.runRequested.connect(self._run)
        self.system.outputReady.connect(self._on_output)
        self.system.errorOccurred.connect(self._on_error)

    def _run(self, text: str) -> None:
        self.system.execute_engine("code_generation", text)

    def _on_output(self, text: str) -> None:
        # Only update when this tab is active to avoid cross-talk
        if self.isVisible():
            self.output_panel.set_text(text)

    def _on_error(self, msg: str) -> None:
        QtWidgets.QMessageBox.warning(self, "Validation", msg)


class VulnDetectPage(QtWidgets.QWidget):
    def __init__(self, system: GeneratorSystem, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.system = system
        self.input_panel = InputPanel("Paste code to scan for vulnerabilities…")
        self.output_panel = OutputPanel("Vulnerability Report")
        self.table = VulnTable()

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.input_panel)
        layout.addWidget(self.table)
        layout.addWidget(self.output_panel)

        self.input_panel.runRequested.connect(self._run)
        self.system.outputReady.connect(self._on_output)
        self.system.errorOccurred.connect(self._on_error)

    def _run(self, text: str) -> None:
        self.system.execute_engine("vulnerability_detection", text)

    def _on_output(self, text: str) -> None:
        if self.isVisible():
            self.output_panel.set_text(text)
            self.table.load_from_json(text)

    def _on_error(self, msg: str) -> None:
        QtWidgets.QMessageBox.warning(self, "Validation", msg)


class SummarizePage(QtWidgets.QWidget):
    def __init__(self, system: GeneratorSystem, parent: Optional[QtWidgets.QWidget] = None) -> None:
        super().__init__(parent)
        self.system = system
        self.input_panel = InputPanel("Paste code or text to summarize…")
        self.output_panel = OutputPanel("Summary / Documentation")

        # Highlight key segments (simple demo: copy to a read-only view)
        self.highlight_view = QtWidgets.QPlainTextEdit()
        self.highlight_view.setReadOnly(True)
        self.highlight_view.setPlaceholderText("(Future) Key segments / highlights will appear here.")

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.input_panel)
        layout.addWidget(self.output_panel)
        layout.addWidget(self.highlight_view)

        self.input_panel.runRequested.connect(self._run)
        self.system.outputReady.connect(self._on_output)
        self.system.errorOccurred.connect(self._on_error)

    def _run(self, text: str) -> None:
        self.system.execute_engine("summarization", text)

    def _on_output(self, text: str) -> None:
        if self.isVisible():
            self.output_panel.set_text(text)
            # TODO: populate highlight_view with actual highlights from real engine
            if not self.highlight_view.toPlainText():
                self.highlight_view.setPlainText("(Stub) No highlights available from the demo summarizer.")

    def _on_error(self, msg: str) -> None:
        QtWidgets.QMessageBox.warning(self, "Validation", msg)


# ------------------------------
# Main Window
# ------------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("AI Generator — Developer Assistant (GUI)")
        self.resize(1200, 800)

        # Controller
        self.system = GeneratorSystem()

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        self.codegen_page = CodeGenPage(self.system)
        self.vuln_page = VulnDetectPage(self.system)
        self.sum_page = SummarizePage(self.system)
        self.tabs.addTab(self.codegen_page, "Generate")
        self.tabs.addTab(self.vuln_page, "Scan")
        self.tabs.addTab(self.sum_page, "Document")
        self.setCentralWidget(self.tabs)

        # Status bar
        self.status = self.statusBar()
        self.status.showMessage("Ready")

        # Log dock
        self.log_dock = QtWidgets.QDockWidget("Logs / Feedback", self)
        self.log_dock.setObjectName("logDock")
        self.log_text = QtWidgets.QPlainTextEdit()
        self.log_text.setReadOnly(True)
        self.log_dock.setWidget(self.log_text)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, self.log_dock)

        # Wire system signals to log
        self.system.outputReady.connect(lambda t: self._log("Output ready (length=%d)" % len(t)))
        self.system.errorOccurred.connect(lambda m: self._log(f"Error: {m}"))

        # Menus
        self._make_menus()

    # --------------------------
    # Menus / Actions
    # --------------------------
    def _make_menus(self) -> None:
        file_menu = self.menuBar().addMenu("&File")
        open_act = QtGui.QAction("Open…", self)
        save_all_act = QtGui.QAction("Save Visible Output", self)
        export_pdf_act = QtGui.QAction("Export Visible Output as PDF", self)
        quit_act = QtGui.QAction("Quit", self)

        open_act.triggered.connect(self._open_into_active_tab)
        save_all_act.triggered.connect(self._save_visible)
        export_pdf_act.triggered.connect(self._export_visible_pdf)
        quit_act.triggered.connect(self.close)

        for a in (open_act, save_all_act, export_pdf_act):
            file_menu.addAction(a)
        file_menu.addSeparator()
        file_menu.addAction(quit_act)

        view_menu = self.menuBar().addMenu("&View")
        toggle_log_act = self.log_dock.toggleViewAction()
        view_menu.addAction(toggle_log_act)

        help_menu = self.menuBar().addMenu("&Help")
        about_act = QtGui.QAction("About", self)
        about_act.triggered.connect(self._about)
        help_menu.addAction(about_act)

    # --------------------------
    # Helpers
    # --------------------------
    def _active_page(self) -> QtWidgets.QWidget:
        return self.tabs.currentWidget()

    def _open_into_active_tab(self) -> None:
        page = self._active_page()
        if isinstance(page, (CodeGenPage, VulnDetectPage, SummarizePage)):
            page.input_panel._on_load()

    def _save_visible(self) -> None:
        page = self._active_page()
        if isinstance(page, CodeGenPage):
            page.output_panel._export("txt")
        elif isinstance(page, VulnDetectPage):
            page.output_panel._export("txt")
        elif isinstance(page, SummarizePage):
            page.output_panel._export("txt")

    def _export_visible_pdf(self) -> None:
        page = self._active_page()
        if isinstance(page, CodeGenPage):
            page.output_panel._export_pdf()
        elif isinstance(page, VulnDetectPage):
            page.output_panel._export_pdf()
        elif isinstance(page, SummarizePage):
            page.output_panel._export_pdf()

    def _about(self) -> None:
        QtWidgets.QMessageBox.information(
            self,
            "About",
            (
                "AI Generator GUI\n\n"
                "Implements the project guide: input & validation, engines (stubs),\n"
                "tabbed UI, export, and error feedback. Replace stubs with real\n"
                "engine calls as they become available."
            ),
        )

    def _log(self, msg: str) -> None:
        self.log_text.appendPlainText(msg)
        self.status.showMessage(msg, 3000)


# ------------------------------
# Entrypoint
# ------------------------------
def main() -> None:
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
