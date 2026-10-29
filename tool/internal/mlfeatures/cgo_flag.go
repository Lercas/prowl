package mlfeatures

// BuiltWithCgo reports the native build mode. Both native and static builds
// compute the training compression feature with zlib level 6.
func BuiltWithCgo() bool { return builtWithCgo }
