package mlfeatures

// BuiltWithCgo reports whether this binary was compiled with cgo. Only the cgo
// path (system zlib) computes compression_ratio byte-identically to the model's
// training environment; callers use this to refuse the in-process scorer on a
// nocgo build rather than silently mis-score short tokens near the threshold.
func BuiltWithCgo() bool { return builtWithCgo }
