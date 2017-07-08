package main

const tpl = `#### #totalhash
{{ if .Results.Sha1 }}
| Found              | URL           |
|:-------------------|:--------------|
| :white_check_mark: | [link](https://totalhash.cymru.com/analysis/?{{ .Results.Sha1 }}) |
{{ else }}
 - Not found
{{- end }}
`

// func printMarkDownTable(th TotalHash) {
// 	fmt.Println("#### #totalhash")
// 	if th.Results.IsEmpty() {
// 		fmt.Println(" - Not found")
// 	} else {
// 		table := clitable.New([]string{"Found", "URL"})
// 		table.AddRow(map[string]interface{}{
// 			"Found": ":white_check_mark:",
// 			"URL":   fmt.Sprintf("[link](%s)", "https://totalhash.cymru.com/analysis/?"+th.Results.Sha1),
// 		})
// 		table.Markdown = true
// 		table.Print()
// 	}
// }
