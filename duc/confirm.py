"""Uniform operator confirmation for CLI/TUI actions.

Only an explicit YES authorizes mutation. NO, blank, unexpected input,
EOF, and Ctrl+C all fail closed. Caller prints the action details first.
No confirmation string is stored in the lifecycle journal.
"""
from __future__ import annotations


def ask_yes_no(question: str, *, input_fn=None, output=print) -> bool:
    """Require the full word 'yes' or 'no'; default is no."""
    if input_fn is None:
        input_fn = input
    try:
        reply = input_fn(f'{question} [yes/no] (default: no): ').strip().lower()
    except (EOFError, KeyboardInterrupt):
        output('Cancelled. No changes authorized.')
        return False
    if reply == 'yes':
        return True
    if reply not in ('no', ''):
        output("Invalid reply. Please answer 'yes' or 'no'. No changes authorized.")
    return False
