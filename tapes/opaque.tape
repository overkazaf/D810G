# D810G Opaque Predicate Detection Demo
Output docs/assets/recordings/opaque.gif
Set Theme "Dracula"
Set FontSize 14
Set Width 900
Set Height 450
Set Padding 20

Type "# D810G — Opaque Predicate Detection"
Enter
Sleep 500ms

Type "cd /Users/nongjiawu/playground/research/re-plugins/D810G"
Enter
Sleep 300ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque 'x == x'"
Enter
Sleep 1500ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque '(x * x) >= 0' --unsigned"
Enter
Sleep 1500ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque '(x & 1) == 2'"
Enter
Sleep 1500ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque '(x & 3) == 4'"
Enter
Sleep 1500ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque 'x > 5'"
Enter
Sleep 1500ms

Type "PYTHONPATH=python python -m d810g_engine cli opaque '(x & 0xff) == 0x41'"
Enter
Sleep 2s

Sleep 2s
