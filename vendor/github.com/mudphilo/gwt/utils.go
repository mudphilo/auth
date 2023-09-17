package jwtfiltergolang

//import  "golang.org/x/exp/slices"

//SliceContains checks if a string slice contains a string
func SliceContains(haystack []string,key string ) bool  {

	// loop through the slice
	for _, r := range haystack {

		// check if key exist
		if r == key {

			// if key exists return true
			return true
		}
	}

	// key does not exist return false
	return false

	//return slices.Contains(haystack,key)
}