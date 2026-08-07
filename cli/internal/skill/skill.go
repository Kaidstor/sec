// Package skill несёт агентский скилл sec (SKILL.md), вкомпилированный в
// бинарь: версия скилла по построению совпадает с версией CLI.
//
// Канонический исходник — SKILL.md в корне репозитория (его видит
// `npx skills add kaidstor/sec` и симлинки dev-машин). go:embed не умеет
// ни `..`, ни симлинки, поэтому здесь лежит копия; рассинхрон ловит
// TestMatchesRepoRoot. Обновить: cp SKILL.md cli/internal/skill/SKILL.md
package skill

import _ "embed"

//go:embed SKILL.md
var MD string
