package skill

import (
	"os"
	"testing"
)

// Копия в этом пакете обязана быть байт-в-байт с корневым SKILL.md —
// go:embed не дотягивается до корня репо (`..` запрещён), поэтому синхрон
// держит этот тест: он гоняется в release.sh до тега.
func TestMatchesRepoRoot(t *testing.T) {
	root, err := os.ReadFile("../../../SKILL.md")
	if err != nil {
		t.Skipf("корневой SKILL.md недоступен (сборка вне репо): %v", err)
	}
	if string(root) != MD {
		t.Fatal("cli/internal/skill/SKILL.md разошёлся с корневым SKILL.md — " +
			"обнови копию: cp SKILL.md cli/internal/skill/SKILL.md")
	}
}
