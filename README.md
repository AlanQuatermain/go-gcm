# Galois/Counter Mode Cipher Operation for Go

Version 1.0 -- 29 Oct 2012

## Introduction

In putting together some tools for the correct handling of [XML Encryption][XMLENC] and [XML Digital Signatures][XMLDSig], I ran across the AES-GCM encryption mode. This is included in the XML-ENC 2.0 working draft in large part due to [problems with the more common CBC mode][cbc-warning] of operation. Sadly, there aren't very many easily-accessible implementations of this algorithm out there, and Go is definitely lacking it. I decided I'd try to write one myself.

The package provided here is designed as if it were a part of the [crypto][go-crypto] package, and thus it operates in conjunction with a block Cipher. It could absolutely be made faster: using Go's concurrency primitives would be one way, and implementing the core GHASH and GCTR algorithms in assembler with SIMD instructions is another. I'll probably look into the former myself, but I doubt I'll go as far as the latter.

[XMLENC]: http://www.w3.org/TR/2012/WD-xmlenc-core1-20121018/
[XMLDSig]: http://www.w3.org/TR/xmldsig-core2/
[cbc-warning]: http://www.w3.org/TR/2012/WD-xmlenc-core1-20121018/#cbc-warning
[go-crypto]: http://golang.org/pkg/crypto/

## Installation

Use `go get github.com/AlanQuatermain/go-gcm` to install, and then import it using `import gcm "github.com/AlanQuatermain/go-gcm"`.

##Documentation

Generated documentation for the package's small API can be seen below.

<!--
	Copyright 2009 The Go Authors. All rights reserved.
	Use of this source code is governed by a BSD-style
	license that can be found in the LICENSE file.
-->

	
<div id="short-nav">
	<dl>
		<dd>
			<code>import gcm "github.com/AlanQuatermain/go-gcm"</code>
		</dd>
	</dl>
	<dl>
		<dd>
			<a href="#overview" class="overviewLink">Overview</a>
		</dd>
		<dd>
			<a href="#index">Index</a>
		</dd>
	</dl>
</div><!-- The package's Name is printed as title by the top-level template -->
<div id="overview" class="toggleVisible">
	<div class="collapsed">
		<h2 class="toggleButton" title="Click to show Overview section">
			Overview ▹
		</h2>
	</div>
	<div class="expanded">
		<h2 class="toggleButton" title="Click to hide Overview section">
			Overview ▾
		</h2>
		<p>
			The GCM package provides an implementation of the Galois/Counter Mode of operation for symmetric block ciphers. It provides authenticated encryption, meaning that it both encrypts content and generates an authentication tag similar to an HMAC operation.
		</p>
	</div>
</div>
<h2 id="index">
	Index
</h2><!-- Table of contents for API; must be named manual-nav to turn off auto nav. -->
<div id="manual-nav">
	<dl>
		<dd>
			<a href="#GaloisCounterMode">type GaloisCounterMode</a>
		</dd>
		<dd>
			&nbsp; &nbsp; <a href="#NewGCM">func NewGCM(b cipher.Block, tagSizeInBits int, iv []byte) (GaloisCounterMode, error)</a>
		</dd>
	</dl>
	<h4>
		Package files
	</h4>
	<p>
		<span style="font-size:90%"><a href="/target/gcm.go">gcm.go</a></span>
	</p>
	<h2 id="GaloisCounterMode">
		type <a href="/target/gcm.go?s=654:1311#L12">GaloisCounterMode</a>
	</h2>
	<pre>
type GaloisCounterMode interface {
    <span class="comment">// BlockSize returns the mode's block size.</span>
    BlockSize() int
    <span class="comment">// Encrypts plaintext along with some additional authenticated data, returning</span>
    <span class="comment">// the encrypted output along with an authentication tag.</span>
    Encrypt(src io.Reader, aad []byte) (enc, tag []byte)
    <span class="comment">// Decrypts data encoded by Encrypt(). Input also requires the additional</span>
    <span class="comment">// authenticated data passed to Encrypt() and the authentication tag returned</span>
    <span class="comment">// by that function. Internally the tag is verified before any attempt is made</span>
    <span class="comment">// do actually decrypt the input ciphertext.</span>
    Decrypt(ciphertext, aad, tag []byte) ([]byte, error)
}
</pre>
	<p>
		This cryptography mode encompasses both encryption and authentication of data. Due to its differing inputs and outputs, it doesn't conform to the cipher.Cipher interface, instead providing separate Encrypt() and Decrypt() methods.
	</p>
	<h3 id="NewGCM">
		func <a href="/target/gcm.go?s=1754:1838#L45">NewGCM</a>
	</h3>
	<pre>
func NewGCM(b cipher.Block, tagSizeInBits int, iv []byte) (GaloisCounterMode, error)
</pre>
	<p>
		Creates a new Galois/Counter Mode for a given block cipher. The iv parameter is required, but a tagSizeInBits of zero can be supplied, in which case the default tag size of 128 bits will be used,
	</p>
</div>
