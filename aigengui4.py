import sys
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol

from PySide6 import QtCore, QtGui, QtWidgets

APP_STYLE = """
QMainWindow { background-color: #020617; }
QTabWidget::pane { border: 1px solid #1f2937; border-radius: 10px; background: #020617; }
QTabBar::tab { background: #020617; color: #9ca3af; padding: 8px 24px; margin: 4px; border-radius: 16px; font-weight: 600; }
QTabBar::tab:selected { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #22c55e, stop:1 #0ea5e9); color: #0b1120; }
QPlainTextEdit { background-color: #020617; color: #e5e7eb; border: 1px solid #1f2937; border-radius: 10px; padding: 8px; }
QTableWidget { background-color: #020617; color: #e5e7eb; border: 1px solid #1f2937; border-radius: 10px; }
QHeaderView::section { background-color: #020617; color: #9ca3af; padding: 6px; border: 0px; border-bottom: 1px solid #1f2937; }
QPushButton { background-color: #0f172a; color: #e5e7eb; border-radius: 999px; padding: 8px 18px; font-weight: 600; border: 1px solid #1f2937; }
QPushButton:hover { border-color: #22c55e; }
QStatusBar { background-color: #020617; color: #6b7280; }
"""


class Engine(Protocol):
    def process(self, data: str) -> str:
        ...


class CodeGenerationEngine:
    def process(self, data: str) -> str:
        return "# Generated code (stub)\n" + data


class VulnerabilityDetectionEngine:
    def process(self, data: str) -> str:
        return json.dumps({
            "issues": [
                {"id": "VULN-001", "title": "SQL Injection", "severity": "HIGH", "line": 34},
                {"id": "VULN-002", "title": "Hardcoded Secret", "severity": "CRITICAL", "line": 7},
            ]
        }, indent=2)


@dataclass
class ValidationResult:
    ok: bool
    message: str = ""


class GeneratorSystem(QtCore.QObject):
    outputReady = QtCore.Signal(str)
    errorOccurred = QtCore.Signal(str)

    def __init__(self, engines: Optional[dict[str, Engine]] = None):
        super().__init__()
        self._engines = engines or {
            "code_generation": CodeGenerationEngine(),
            "vulnerability_detection": VulnerabilityDetectionEngine(),
        }

    def validate_input(self, text: str) -> ValidationResult:
        if not text.strip():
            return ValidationResult(False, "Input is empty")
        return ValidationResult(True)

    def execute_engine(self, key: str, text: str):
        v = self.validate_input(text)
        if not v.ok:
            self.errorOccurred.emit(v.message)
            return
        try:
            self.outputReady.emit(self._engines[key].process(text))
        except Exception as e:
            self.errorOccurred.emit(str(e))


class InputPanel(QtWidgets.QWidget):
    runRequested = QtCore.Signal(str)

    def __init__(self, placeholder: str):
        super().__init__()
        self.editor = QtWidgets.QPlainTextEdit()
        self.editor.setPlaceholderText(placeholder)
        self.editor.setMinimumHeight(220)
        self.editor.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))

        self.load_btn = QtWidgets.QPushButton("Load")
        self.run_btn = QtWidgets.QPushButton("Run")

        row = QtWidgets.QHBoxLayout()
        row.addWidget(self.load_btn)
        row.addStretch(1)
        row.addWidget(self.run_btn)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.editor)
        layout.addLayout(row)

        self.load_btn.clicked.connect(self._on_load)
        self.run_btn.clicked.connect(self._on_run)

    def _on_load(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open", str(Path.home()))
        if path:
            self.editor.setPlainText(Path(path).read_text(errors="ignore"))

    def _on_run(self):
        self.runRequested.emit(self.editor.toPlainText())


class OutputPanel(QtWidgets.QWidget):
    def __init__(self, title: str):
        super().__init__()
        self.label = QtWidgets.QLabel(title)
        self.label.setStyleSheet("color: #e5e7eb; font-weight: 600;")
        self.output = QtWidgets.QPlainTextEdit(readOnly=True)
        self.output.setFont(QtGui.QFontDatabase.systemFont(QtGui.QFontDatabase.FixedFont))
        self.save_btn = QtWidgets.QPushButton("Save")

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.label)
        layout.addWidget(self.output)
        layout.addWidget(self.save_btn)

        self.save_btn.clicked.connect(self._export)

    def set_text(self, text: str):
        self.output.setPlainText(text)

    def _export(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save", "output.txt")
        if path:
            Path(path).write_text(self.output.toPlainText())


class VulnTable(QtWidgets.QTableWidget):
    def __init__(self):
        super().__init__(0, 4)
        self.setHorizontalHeaderLabels(["ID", "Title", "Severity", "Line"])
        self.horizontalHeader().setStretchLastSection(True)

    def load_from_json(self, text: str):
        try:
            data = json.loads(text)
        except Exception:
            return
        self.setRowCount(0)
        for issue in data.get("issues", []):
            r = self.rowCount()
            self.insertRow(r)
            self.setItem(r, 0, QtWidgets.QTableWidgetItem(issue.get("id", "")))
            self.setItem(r, 1, QtWidgets.QTableWidgetItem(issue.get("title", "")))
            sev = issue.get("severity", "")
            item_sev = QtWidgets.QTableWidgetItem(sev)
            if sev.upper() in ("HIGH", "CRITICAL"):
                item_sev.setForeground(QtGui.QColor("#f97316"))
            elif sev.upper() == "MEDIUM":
                item_sev.setForeground(QtGui.QColor("#eab308"))
            else:
                item_sev.setForeground(QtGui.QColor("#22c55e"))
            self.setItem(r, 2, item_sev)
            self.setItem(r, 3, QtWidgets.QTableWidgetItem(str(issue.get("line", ""))))


class CodeGenPage(QtWidgets.QWidget):
    def __init__(self, system: GeneratorSystem, engine_key: str):
        super().__init__()
        self.system = system
        self.engine_key = engine_key
        self.input_panel = InputPanel("Describe what code to generate…")
        self.output_panel = OutputPanel("Generated Code")

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.input_panel)
        layout.addWidget(self.output_panel)

        self.input_panel.runRequested.connect(self._run)
        self.system.outputReady.connect(self._on_output)
        self.system.errorOccurred.connect(self._on_error)

    def _run(self, text: str):
        self.system.execute_engine(self.engine_key, text)

    def _on_output(self, text: str):
        if self.isVisible():
            self.output_panel.set_text(text)

    def _on_error(self, msg: str):
        QtWidgets.QMessageBox.warning(self, "Error", msg)


class VulnerabilityPage(QtWidgets.QWidget):
    def __init__(self, system: GeneratorSystem, engine_key: str):
        super().__init__()
        self.system = system
        self.engine_key = engine_key
        self.input_panel = InputPanel("Paste code to scan…")
        self.table = VulnTable()
        self.output_panel = OutputPanel("Raw Report")

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.input_panel)
        layout.addWidget(self.table)
        layout.addWidget(self.output_panel)

        self.input_panel.runRequested.connect(self._run)
        self.system.outputReady.connect(self._on_output)
        self.system.errorOccurred.connect(self._on_error)

    def _run(self, text: str):
        self.system.execute_engine(self.engine_key, text)

    def _on_output(self, text: str):
        if self.isVisible():
            self.output_panel.set_text(text)
            self.table.load_from_json(text)

    def _on_error(self, msg: str):
        QtWidgets.QMessageBox.warning(self, "Error", msg)


class HeaderBar(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        subtitle = QtWidgets.QLabel("Code + Vulnerability Assistant")
        chip = QtWidgets.QLabel("v1.0")

        subtitle_font = QtGui.QFont("Segoe UI", 11)
        subtitle.setFont(subtitle_font)
        subtitle.setStyleSheet("color: #e5e7eb;")

        chip.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #22c55e, stop:1 #0ea5e9);"
            "color: #020617; padding: 4px 12px; border-radius: 999px; font-weight: 600;"
        )

        row = QtWidgets.QHBoxLayout(self)
        row.addWidget(subtitle)
        row.addStretch(1)
        row.addWidget(chip)
        row.setContentsMargins(8, 8, 8, 8)


class AccentLine(QtWidgets.QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(2)
        self.setStyleSheet(
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #22c55e, stop:1 #0ea5e9);"
            "border: none;"
        )


TAB_DEFS: list[tuple[str, str, type[QtWidgets.QWidget]]] = [
    ("Generate", "code_generation", CodeGenPage),
    ("Vulnerability Detector", "vulnerability_detection", VulnerabilityPage),
]


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Generator")
        self.resize(1100, 750)
        self.setStyleSheet(APP_STYLE)

        self.system = GeneratorSystem()
        self.tabs = QtWidgets.QTabWidget()

        for label, engine_key, page_cls in TAB_DEFS:
            page = page_cls(self.system, engine_key)
            self.tabs.addTab(page, label)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)
        layout.addWidget(HeaderBar())
        layout.addWidget(AccentLine())
        layout.addWidget(self.tabs)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        self.setCentralWidget(central)

        self.status = self.statusBar()
        self.status.showMessage("Ready")


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()