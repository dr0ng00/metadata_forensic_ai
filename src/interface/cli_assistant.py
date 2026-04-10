"""Command-line assistant for interactive forensic analysis.

Provides `ForensicCLIAssistant` for querying analysis results using natural language-like commands.
"""
from typing import Any, Dict

from .natural_language_processor import NaturalLanguageProcessor


class ForensicCLIAssistant:
    """CLI assistant for interactive forensic investigation."""
    
    def __init__(self, analyzer: Any | None = None, analysis_results: Dict[str, Any] | None = None, forensic_system: Any | None = None):
        self.analyzer = analyzer
        self.analysis_results = analysis_results or {}
        self.forensic_system = forensic_system
        self.running = False
        self.nlp = NaturalLanguageProcessor()

    def start_session(self) -> None:
        """Initialize a professional forensic investigation session."""
        print("\n--- MetaForensicAI Enterprise: Investigative Interface v1.0.0 ---")
        print("Ask in natural language, short prompts, or broken English. Type 'help' for CLI controls.")
        if self.analysis_results:
            suggested = self.nlp.get_suggested_questions(self.analysis_results)
            if suggested:
                print("\nExamples:")
                for question in suggested[:4]:
                    print(f"- {question}")
        
        self.running = True
        while self.running:
            try:
                command = input("\nDetectQuery> ").strip()
                if command:
                    response = self.run_command(command)
                    print(response)
            except (KeyboardInterrupt, EOFError):
                self.stop()

    def stop(self) -> None:
        self.running = False
        print("\nSession ended.")

    def run_command(self, command: str) -> str:
        cmd = command.strip().lower()
        
        if cmd in ['exit', 'quit']:
            self.stop()
            return "Exiting interactive mode."
            
        if cmd == 'help':
            return """Forensic Assistant Commands:
- report: Provide a comprehensive analytical summary of the evidence.
- mode <name>: Change explanation mode. Valid: basic, forensic, security, legal.
- Any other natural-language question is handled by the same chatbox pipeline used in the GUI.
- exit: Terminate the current investigative session."""

        if not self.analysis_results:
            return "No analysis results loaded. Please run analysis first."

        if cmd == 'report':
            return self._format_summary()

        if cmd.startswith('mode '):
            new_mode = cmd.replace('mode ', '').strip()
            # Map simple names to full mode keys
            mode_map = {
                'basic': 'explain_basic',
                'forensic': 'explain_forensic',
                'security': 'explain_security',
                'legal': 'explain_legal'
            }
            target_mode = mode_map.get(new_mode, new_mode)
            if self.nlp.set_mode(target_mode):
                return f"ACTIVE MODE UPDATED: Now operating in '{target_mode}' configuration."
            else:
                return f"ERROR: '{new_mode}' is not a valid forensic mode. Valid: basic, forensic, security, legal."

        parsed = self.nlp.parse(command)
        return self.nlp.respond(parsed, self.analysis_results)

    def _format_summary(self) -> str:
        res = self.analysis_results
        risk = res.get('risk_assessment', {})
        origin = res.get('origin_detection', {})
        
        return (f"\n--- Forensic Evidence Summary ---\n"
                f"Evidence Path: {res.get('evidence_integrity', {}).get('file_path', 'Unknown')}\n"
                f"Source Identification: {origin.get('primary_origin', 'Unknown')} (Confidence: {origin.get('confidence', 0)*100:.1f}%)\n"
                f"Analytical Risk Score: {risk.get('risk_score', 0)}/100\n"
                f"Categorical Risk Level: {risk.get('level', 'LOW')}\n"
                f"Temporal Signature: {res.get('analysis_timestamp')}\n"
                f"---------------------------------\n")


__all__ = ['ForensicCLIAssistant']
