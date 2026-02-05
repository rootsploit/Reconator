package aiguided

import (
	"fmt"
	"sort"
	"strings"
)

// TOON (Token-Oriented Object Notation) encoder for efficient LLM prompts
// Reduces token consumption by 30-60% compared to JSON
// Based on: github.com/toon-format/toon
//
// Key features:
// - YAML-style indentation for nested objects
// - CSV-style tabular layout for uniform arrays
// - Explicit field declarations: arrayName[N]{field1,field2}:
// - Minimal syntax (no braces/brackets for objects)
//
// Example conversion:
// JSON: {"users": [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]}
// TOON: users[2]{id,name}:
//         1,Alice
//         2,Bob

// ToonEncoder converts data structures to TOON format
type ToonEncoder struct {
	indent int
}

// NewToonEncoder creates a new TOON encoder
func NewToonEncoder() *ToonEncoder {
	return &ToonEncoder{indent: 0}
}

// EncodeObject encodes a map[string]interface{} to TOON format
func (e *ToonEncoder) EncodeObject(data map[string]interface{}) string {
	var result strings.Builder
	e.encodeObjectInternal(data, &result, 0)
	return result.String()
}

func (e *ToonEncoder) encodeObjectInternal(data map[string]interface{}, result *strings.Builder, indentLevel int) {
	// Sort keys for deterministic output
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		value := data[key]
		indent := strings.Repeat("  ", indentLevel)

		switch v := value.(type) {
		case map[string]interface{}:
			// Nested object
			result.WriteString(fmt.Sprintf("%s%s:\n", indent, key))
			e.encodeObjectInternal(v, result, indentLevel+1)

		case []interface{}:
			// Array
			if len(v) == 0 {
				result.WriteString(fmt.Sprintf("%s%s[0]:\n", indent, key))
				continue
			}

			// Check if array elements are uniform objects
			if isUniformObjectArray(v) {
				e.encodeUniformArray(key, v, result, indentLevel)
			} else {
				// Non-uniform array (mixed types or primitives)
				e.encodeGenericArray(key, v, result, indentLevel)
			}

		case []string:
			// String array (common case)
			result.WriteString(fmt.Sprintf("%s%s[%d]: %s\n", indent, key, len(v), strings.Join(v, ", ")))

		case string:
			result.WriteString(fmt.Sprintf("%s%s: %s\n", indent, key, v))

		case int, int64, float64, bool:
			result.WriteString(fmt.Sprintf("%s%s: %v\n", indent, key, v))

		default:
			// Fallback to string representation
			result.WriteString(fmt.Sprintf("%s%s: %v\n", indent, key, v))
		}
	}
}

// isUniformObjectArray checks if all elements are objects with the same keys
func isUniformObjectArray(arr []interface{}) bool {
	if len(arr) == 0 {
		return false
	}

	// Check if first element is an object
	firstObj, ok := arr[0].(map[string]interface{})
	if !ok {
		return false
	}

	// Get keys from first object
	firstKeys := make([]string, 0, len(firstObj))
	for k := range firstObj {
		firstKeys = append(firstKeys, k)
	}
	sort.Strings(firstKeys)

	// Check all elements have same keys
	for i := 1; i < len(arr); i++ {
		obj, ok := arr[i].(map[string]interface{})
		if !ok {
			return false
		}

		if len(obj) != len(firstKeys) {
			return false
		}

		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for j, k := range firstKeys {
			if keys[j] != k {
				return false
			}
		}
	}

	return true
}

// encodeUniformArray encodes an array of uniform objects in tabular format
func (e *ToonEncoder) encodeUniformArray(key string, arr []interface{}, result *strings.Builder, indentLevel int) {
	if len(arr) == 0 {
		return
	}

	indent := strings.Repeat("  ", indentLevel)

	// Get field names from first object
	firstObj := arr[0].(map[string]interface{})
	fields := make([]string, 0, len(firstObj))
	for k := range firstObj {
		fields = append(fields, k)
	}
	sort.Strings(fields)

	// Write array declaration with field names
	result.WriteString(fmt.Sprintf("%s%s[%d]{%s}:\n", indent, key, len(arr), strings.Join(fields, ",")))

	// Write each row
	rowIndent := strings.Repeat("  ", indentLevel+1)
	for _, elem := range arr {
		obj := elem.(map[string]interface{})
		values := make([]string, 0, len(fields))
		for _, field := range fields {
			val := obj[field]
			values = append(values, formatValue(val))
		}
		result.WriteString(fmt.Sprintf("%s%s\n", rowIndent, strings.Join(values, ",")))
	}
}

// encodeGenericArray encodes a non-uniform array
func (e *ToonEncoder) encodeGenericArray(key string, arr []interface{}, result *strings.Builder, indentLevel int) {
	indent := strings.Repeat("  ", indentLevel)
	result.WriteString(fmt.Sprintf("%s%s[%d]:\n", indent, key, len(arr)))

	itemIndent := strings.Repeat("  ", indentLevel+1)
	for i, elem := range arr {
		switch v := elem.(type) {
		case map[string]interface{}:
			result.WriteString(fmt.Sprintf("%s[%d]:\n", itemIndent, i))
			e.encodeObjectInternal(v, result, indentLevel+2)
		case string:
			result.WriteString(fmt.Sprintf("%s%s\n", itemIndent, v))
		default:
			result.WriteString(fmt.Sprintf("%s%v\n", itemIndent, v))
		}
	}
}

// formatValue formats a value for CSV-style output
func formatValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		// Escape commas and newlines
		if strings.Contains(v, ",") || strings.Contains(v, "\n") {
			return fmt.Sprintf("\"%s\"", strings.ReplaceAll(v, "\"", "\"\""))
		}
		return v
	case int, int64:
		return fmt.Sprintf("%d", v)
	case float64:
		// Remove trailing zeros
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), ".")
	case bool:
		return fmt.Sprintf("%t", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Helper functions for building TOON structures

// ToonObject creates a TOON-encoded object from key-value pairs
func ToonObject(data map[string]interface{}) string {
	encoder := NewToonEncoder()
	return encoder.EncodeObject(data)
}

// ToonArray creates a TOON-encoded array declaration
func ToonArray(name string, items []map[string]interface{}, fields ...string) string {
	if len(items) == 0 {
		return fmt.Sprintf("%s[0]:\n", name)
	}

	// If no fields specified, extract from first item
	if len(fields) == 0 {
		for k := range items[0] {
			fields = append(fields, k)
		}
		sort.Strings(fields)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s[%d]{%s}:\n", name, len(items), strings.Join(fields, ",")))

	for _, item := range items {
		values := make([]string, 0, len(fields))
		for _, field := range fields {
			values = append(values, formatValue(item[field]))
		}
		result.WriteString(fmt.Sprintf("  %s\n", strings.Join(values, ",")))
	}

	return result.String()
}

// ToonList creates a simple comma-separated list
func ToonList(name string, items []string) string {
	if len(items) == 0 {
		return fmt.Sprintf("%s[0]:\n", name)
	}
	return fmt.Sprintf("%s[%d]: %s\n", name, len(items), strings.Join(items, ", "))
}

// ToonField creates a simple key-value field
func ToonField(key string, value interface{}) string {
	return fmt.Sprintf("%s: %v\n", key, value)
}

// ToonSection creates an indented section
func ToonSection(name string, content string) string {
	if content == "" {
		return fmt.Sprintf("%s:\n", name)
	}

	// Indent all content lines
	lines := strings.Split(strings.TrimSpace(content), "\n")
	indented := make([]string, len(lines))
	for i, line := range lines {
		indented[i] = "  " + line
	}

	return fmt.Sprintf("%s:\n%s\n", name, strings.Join(indented, "\n"))
}
