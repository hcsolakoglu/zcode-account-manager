package model

import "testing"

func TestNormalizeAdapterMetadataMigratesLegacyRecords(t *testing.T) {
	metadata, err := NormalizeAdapterMetadata(AdapterMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.StateGroup != StateGroupID || metadata.Product != ProductDesktop || metadata.SchemaVersion != SchemaVersion {
		t.Fatalf("migrated metadata = %+v", metadata)
	}
}

func TestNormalizeAdapterMetadataRejectsForeignStateGroup(t *testing.T) {
	if _, err := NormalizeAdapterMetadata(AdapterMetadata{Product: ProductDesktop, StateGroup: "other", SchemaVersion: SchemaVersion}); err == nil {
		t.Fatal("foreign state group accepted")
	}
}
