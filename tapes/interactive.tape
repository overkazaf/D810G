# D810G Interactive Rule Editor Demo
Output docs/assets/recordings/interactive.gif
Set Theme "Dracula"
Set FontSize 14
Set Width 900
Set Height 550
Set Padding 20

Type "# D810G — Interactive Rule Editor"
Enter
Sleep 500ms

Type "cd /Users/nongjiawu/playground/research/re-plugins/D810G"
Enter
Sleep 300ms

Type "PYTHONPATH=python python -m d810g_engine cli interactive"
Enter
Sleep 2s

Type "test (x | y) - (x & y)"
Enter
Sleep 2s

Type "test (x & ~y) | (~x & y)"
Enter
Sleep 2s

Type "verify (x & y) + (x ^ y) = x | y"
Enter
Sleep 2s

Type "add my_demorgan ~(~x & ~y) = x | y"
Enter
Sleep 2s

Type "test ~(~x & ~y)"
Enter
Sleep 2s

Type "stats"
Enter
Sleep 2s

Type "quit"
Enter
Sleep 1s
