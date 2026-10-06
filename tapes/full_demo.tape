# D810G Full Demo Suite
Output docs/assets/recordings/full_demo.gif
Set Theme "Dracula"
Set FontSize 14
Set Width 1000
Set Height 600
Set Padding 20

Type "# D810G — Complete Demo Suite"
Enter
Sleep 500ms

Type "cd /Users/nongjiawu/playground/research/re-plugins/D810G"
Enter
Sleep 300ms

Type "# 1. MBA Simplification"
Enter
Sleep 300ms
Type "PYTHONPATH=python python -m d810g_engine cli simplify '(x | y) - (x & y)'"
Enter
Sleep 2s

Type "# 2. Deep Multi-Pass"
Enter
Sleep 300ms
Type "PYTHONPATH=python python -m d810g_engine cli simplify --deep '((x | y) - (x & y)) ^ ((x | y) - (x & y))'"
Enter
Sleep 3s

Type "# 3. Opaque Predicates"
Enter
Sleep 300ms
Type "PYTHONPATH=python python -m d810g_engine cli opaque 'x == x'"
Enter
Sleep 1500ms
Type "PYTHONPATH=python python -m d810g_engine cli opaque '(x & 1) == 2'"
Enter
Sleep 1500ms
Type "PYTHONPATH=python python -m d810g_engine cli opaque 'x > 5'"
Enter
Sleep 1500ms

Type "# 4. Run All Tests"
Enter
Sleep 300ms
Type "PYTHONPATH=python python -m pytest test/ -q"
Enter
Sleep 3s

Sleep 2s
