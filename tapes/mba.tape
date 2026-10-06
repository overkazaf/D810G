# D810G MBA Simplification Demo
Output docs/assets/recordings/mba.gif
Set Theme "Dracula"
Set FontSize 14
Set Width 900
Set Height 500
Set Padding 20

Type "# D810G — MBA Expression Simplification"
Enter
Sleep 500ms

Type "cd /Users/nongjiawu/playground/research/re-plugins/D810G"
Enter
Sleep 300ms

Type "PYTHONPATH=python python -m d810g_engine cli simplify '(x | y) - (x & y)'"
Enter
Sleep 2s

Type "PYTHONPATH=python python -m d810g_engine cli simplify '(x & ~y) | (~x & y)'"
Enter
Sleep 2s

Type "PYTHONPATH=python python -m d810g_engine cli simplify '(x | y) + (x & y)'"
Enter
Sleep 2s

Type "# Multi-pass deep simplification"
Enter
Sleep 500ms

Type "PYTHONPATH=python python -m d810g_engine cli simplify --deep '((x | y) - (x & y)) ^ ((x | y) - (x & y))'"
Enter
Sleep 3s

Sleep 2s
