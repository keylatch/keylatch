// export_test.go makes internal check constructors accessible to tests
// in the doctor_test package. Only used during testing.
package doctor

// ExportCheckIntegrationMarkers exposes checkIntegrationMarkers for unit tests.
func ExportCheckIntegrationMarkers() Check {
	return checkIntegrationMarkers()
}
