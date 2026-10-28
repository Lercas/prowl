package mlfeatures

import (
	"reflect"
	"testing"
)

func TestFeatureExtractionDeterministic(t *testing.T) {
	for _, value := range []string{"Autumn!7Road", "ПарольСентябрь42", "aabbccddefghij", "abAB01-_!"} {
		want := Extract(value, Context{})
		for i := 0; i < 100; i++ {
			if got := Extract(value, Context{}); !reflect.DeepEqual(got, want) {
				t.Fatalf("feature calculation changed on repetition %d", i)
			}
		}
	}
}
