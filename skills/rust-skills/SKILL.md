---
name: rust-skills
description: >
  Comprehensive Rust coding guidelines with 265 rules across 26 categories.
  Use when writing, reviewing, or refactoring Rust code. Covers ownership,
  error handling, async patterns, concurrency, unsafe code, API design, memory
  optimization, performance, numeric safety, conversions, serde, pattern
  matching, macros, closures, observability, testing, and common anti-patterns.
  Invoke with /rust-skills.
license: MIT
metadata:
  author: leonardomso
  version: "1.5.1"
  sources:
    - Rust API Guidelines
    - Rust Performance Book
    - Rust 2024 Edition Guide
    - The Rustonomicon
    - ripgrep, tokio, serde, polars, axum, cargo codebases
---

# Rust Best Practices

Comprehensive guide for writing high-quality, idiomatic, and highly optimized Rust code. Contains 265 rules across 26 categories, prioritized by impact to guide LLMs in code generation and refactoring. Current for Rust 1.96 (2024 edition).

## When to Apply

Reference these guidelines when:
- Writing new Rust functions, structs, or modules
- Implementing error handling or async code
- Writing concurrent, parallel, or `unsafe` code
- Designing public APIs for libraries
- Reviewing code for ownership/borrowing issues
- Optimizing memory usage or reducing allocations
- Tuning performance for hot paths
- Refactoring existing Rust code

## Rule Categories by Priority

| Priority | Category | Impact | Prefix | Rules |
|----------|----------|--------|--------|-------|
| 1 | Ownership & Borrowing | CRITICAL | `own-` | 12 |
| 2 | Error Handling | CRITICAL | `err-` | 12 |
| 3 | Memory Optimization | CRITICAL | `mem-` | 17 |
| 4 | Unsafe Code | CRITICAL | `unsafe-` | 7 |
| 5 | API Design | HIGH | `api-` | 17 |
| 6 | Async/Await | HIGH | `async-` | 18 |
| 7 | Concurrency | HIGH | `conc-` | 4 |
| 8 | Compiler Optimization | HIGH | `opt-` | 12 |
| 9 | Numeric & Arithmetic Safety | HIGH | `num-` | 5 |
| 10 | Type Safety | MEDIUM | `type-` | 13 |
| 11 | Trait & Generics Design | MEDIUM | `trait-` | 6 |
| 12 | Conversions | MEDIUM | `conv-` | 3 |
| 13 | Const & Compile-Time | MEDIUM | `const-` | 4 |
| 14 | Serde | MEDIUM | `serde-` | 8 |
| 15 | Pattern Matching | MEDIUM | `pat-` | 5 |
| 16 | Macros | MEDIUM | `macro-` | 8 |
| 17 | Closures | MEDIUM | `closure-` | 5 |
| 18 | Collections | MEDIUM | `coll-` | 4 |
| 19 | Naming Conventions | MEDIUM | `name-` | 16 |
| 20 | Testing | MEDIUM | `test-` | 15 |
| 21 | Documentation | MEDIUM | `doc-` | 12 |
| 22 | Observability | MEDIUM | `obs-` | 7 |
| 23 | Performance Patterns | MEDIUM | `perf-` | 13 |
| 24 | Project Structure | LOW | `proj-` | 14 |
| 25 | Clippy & Linting | LOW | `lint-` | 13 |
| 26 | Anti-patterns | REFERENCE | `anti-` | 15 |

---

## Quick Reference

### 1. Ownership & Borrowing (CRITICAL)

- [`own-borrow-over-clone`](rules/own-borrow-over-clone.md) - Prefer `&T` borrowing over `.clone()`
- [`own-slice-over-vec`](rules/own-slice-over-vec.md) - Accept `&[T]` not `&Vec<T>`, `&str` not `&String`
- [`own-cow-conditional`](rules/own-cow-conditional.md) - Use `Cow<'a, T>` for conditional ownership
- [`own-arc-shared`](rules/own-arc-shared.md) - Use `Arc<T>` for thread-safe shared ownership
- [`own-rc-single-thread`](rules/own-rc-single-thread.md) - Use `Rc<T>` for shared ownership in single-threaded contexts
- [`own-refcell-interior`](rules/own-refcell-interior.md) - Use `RefCell<T>` for interior mutability in single-threaded code
- [`own-mutex-interior`](rules/own-mutex-interior.md) - Use `Mutex<T>` for interior mutability across threads
- [`own-rwlock-readers`](rules/own-rwlock-readers.md) - Use `RwLock<T>` when reads significantly outnumber writes
- [`own-copy-small`](rules/own-copy-small.md) - Implement `Copy` for small, simple types
- [`own-clone-explicit`](rules/own-clone-explicit.md) - Use explicit `Clone` for types where copying has meaningful cost
- [`own-move-large`](rules/own-move-large.md) - Move large types instead of copying; use `Box` if moves are expensive
- [`own-lifetime-elision`](rules/own-lifetime-elision.md) - Rely on lifetime elision rules; add explicit lifetimes only when required

### 2. Error Handling (CRITICAL)

- [`err-thiserror-lib`](rules/err-thiserror-lib.md) - Use `thiserror` for library error types
- [`err-anyhow-app`](rules/err-anyhow-app.md) - Use `anyhow` for application error handling
- [`err-result-over-panic`](rules/err-result-over-panic.md) - Return `Result<T, E>` instead of panicking for recoverable errors
- [`err-context-chain`](rules/err-context-chain.md) - Add context with `.context()` or `.with_context()`
- [`err-no-unwrap-prod`](rules/err-no-unwrap-prod.md) - Avoid `unwrap()` in production code; use `?`, `expect()`, or handle errors
- [`err-expect-bugs-only`](rules/err-expect-bugs-only.md) - Use `expect()` only for invariants that indicate bugs, not user errors
- [`err-question-mark`](rules/err-question-mark.md) - Use `?` operator for clean propagation
- [`err-from-impl`](rules/err-from-impl.md) - Implement `From<E>` for error conversions to enable `?` operator
- [`err-source-chain`](rules/err-source-chain.md) - Preserve error chains with `#[source]` or `source()` method
- [`err-lowercase-msg`](rules/err-lowercase-msg.md) - Start error messages lowercase, no trailing punctuation
- [`err-doc-errors`](rules/err-doc-errors.md) - Document error conditions with `# Errors` section in doc comments
- [`err-custom-type`](rules/err-custom-type.md) - Define custom error types for domain-specific failures

### 3. Memory Optimization (CRITICAL)

- [`mem-with-capacity`](rules/mem-with-capacity.md) - Use `with_capacity()` when size is known
- [`mem-smallvec`](rules/mem-smallvec.md) - Use `SmallVec` for usually-small collections
- [`mem-arrayvec`](rules/mem-arrayvec.md) - Use `ArrayVec<T, N>` for fixed-capacity collections that never heap-allocate
- [`mem-box-large-variant`](rules/mem-box-large-variant.md) - Box large enum variants to reduce overall enum size
- [`mem-boxed-slice`](rules/mem-boxed-slice.md) - Use `Box<[T]>` instead of `Vec<T>` for fixed-size heap data
- [`mem-thinvec`](rules/mem-thinvec.md) - Use `ThinVec<T>` for nullable collections with minimal overhead
- [`mem-clone-from`](rules/mem-clone-from.md) - Use `clone_from()` to reuse allocations when repeatedly cloning
- [`mem-reuse-collections`](rules/mem-reuse-collections.md) - Clear and reuse collections instead of creating new ones in loops
- [`mem-avoid-format`](rules/mem-avoid-format.md) - Avoid `format!()` when string literals work
- [`mem-write-over-format`](rules/mem-write-over-format.md) - Use `write!()` into existing buffers instead of `format!()` allocations
- [`mem-arena-allocator`](rules/mem-arena-allocator.md) - Use arena allocators for batch allocations
- [`mem-zero-copy`](rules/mem-zero-copy.md) - Use zero-copy patterns with slices and `Bytes`
- [`mem-compact-string`](rules/mem-compact-string.md) - Use compact string types for memory-constrained string storage
- [`mem-smaller-integers`](rules/mem-smaller-integers.md) - Use appropriately-sized integers to reduce memory footprint
- [`mem-assert-type-size`](rules/mem-assert-type-size.md) - Use static assertions to guard against accidental type size growth
- [`mem-take-replace`](rules/mem-take-replace.md) - Use `mem::take` / `mem::replace` to move a value out of a `&mut` without cloning
- [`mem-drop-order`](rules/mem-drop-order.md) - Know and control drop order: struct fields drop top-to-bottom, locals in reverse

### 4. Unsafe Code (CRITICAL)

- [`unsafe-safety-comment`](rules/unsafe-safety-comment.md) - Write a `// SAFETY:` comment above every `unsafe` block and a `# Safety` section in every `unsafe fn`.
- [`unsafe-minimize-scope`](rules/unsafe-minimize-scope.md) - Keep `unsafe` blocks as small as possible â€” mark only the operation that requires unsafety, not the surrounding safe code.
- [`unsafe-miri-ci`](rules/unsafe-miri-ci.md) - Run `cargo miri test` in CI for every crate that contains `unsafe` code.
- [`unsafe-maybeuninit`](rules/unsafe-maybeuninit.md) - Use `MaybeUninit<T>` for uninitialized memory; never use `mem::uninitialized()` or `mem::zeroed()` for types with validity invariants.
- [`unsafe-extern-block`](rules/unsafe-extern-block.md) - In Rust 2024, wrap `extern` blocks in `unsafe extern { }` and annotate each item as `safe` or `unsafe`.
- [`unsafe-send-sync-manual`](rules/unsafe-send-sync-manual.md) - Document the invariants when manually implementing `Send` or `Sync`; prefer letting the compiler derive them automatically.
- [`unsafe-no-mangle-unsafe`](rules/unsafe-no-mangle-unsafe.md) - In Rust 2024, write `#[unsafe(no_mangle)]`, `#[unsafe(export_name = "...")]`, and `#[unsafe(link_section = "...")]` â€” not the bare attribute forms.

### 5. API Design (HIGH)

- [`api-builder-pattern`](rules/api-builder-pattern.md) - Use Builder pattern for complex construction
- [`api-builder-must-use`](rules/api-builder-must-use.md) - Mark builder methods with `#[must_use]` to prevent silent drops
- [`api-newtype-safety`](rules/api-newtype-safety.md) - Use newtypes to prevent mixing semantically different values
- [`api-typestate`](rules/api-typestate.md) - Use typestate pattern to encode state machine invariants in the type system
- [`api-sealed-trait`](rules/api-sealed-trait.md) - Use sealed traits to prevent external implementations while allowing use
- [`api-extension-trait`](rules/api-extension-trait.md) - Use extension traits to add methods to external types
- [`api-parse-dont-validate`](rules/api-parse-dont-validate.md) - Parse into validated types at boundaries
- [`api-impl-into`](rules/api-impl-into.md) - Accept `impl Into<T>` for flexible APIs, implement `From<T>` for conversions
- [`api-impl-asref`](rules/api-impl-asref.md) - Use `AsRef<T>` when you only need to borrow the inner data
- [`api-must-use`](rules/api-must-use.md) - Mark types and functions with `#[must_use]` when ignoring results is likely a bug
- [`api-non-exhaustive`](rules/api-non-exhaustive.md) - Use `#[non_exhaustive]` on public enums and structs for forward compatibility
- [`api-from-not-into`](rules/api-from-not-into.md) - Implement `From<T>`, not `Into<U>` - From gives you Into for free
- [`api-default-impl`](rules/api-default-impl.md) - Implement `Default` for types with sensible default values
- [`api-common-traits`](rules/api-common-traits.md) - Implement standard traits (Debug, Clone, PartialEq, etc.) for public types
- [`api-serde-optional`](rules/api-serde-optional.md) - Make serde a feature flag, not a hard dependency for library crates
- [`api-impl-fromiterator`](rules/api-impl-fromiterator.md) - Implement `FromIterator` and `Extend` for collection types, and `IntoIterator` for all three reference forms
- [`api-operator-overload`](rules/api-operator-overload.md) - Overload operators only when the semantics are natural and unsurprising

### 6. Async/Await (HIGH)

- [`async-tokio-runtime`](rules/async-tokio-runtime.md) - Configure Tokio runtime appropriately for your workload
- [`async-no-lock-await`](rules/async-no-lock-await.md) - Never hold `Mutex`/`RwLock` across `.await`
- [`async-spawn-blocking`](rules/async-spawn-blocking.md) - Use `spawn_blocking` for CPU-intensive work
- [`async-tokio-fs`](rules/async-tokio-fs.md) - Use `tokio::fs` instead of `std::fs` in async code
- [`async-cancellation-token`](rules/async-cancellation-token.md) - Use `CancellationToken` for graceful shutdown and task cancellation
- [`async-join-parallel`](rules/async-join-parallel.md) - Use `join!` or `try_join!` for concurrent independent futures
- [`async-try-join`](rules/async-try-join.md) - Use `try_join!` for concurrent fallible operations with early return on error
- [`async-select-racing`](rules/async-select-racing.md) - Use `select!` to race futures and handle the first to complete
- [`async-bounded-channel`](rules/async-bounded-channel.md) - Use bounded channels to apply backpressure and prevent unbounded memory growth
- [`async-mpsc-queue`](rules/async-mpsc-queue.md) - Use `mpsc` channels for async message queues between tasks
- [`async-broadcast-pubsub`](rules/async-broadcast-pubsub.md) - Use `broadcast` channel for pub/sub where all subscribers receive all messages
- [`async-watch-latest`](rules/async-watch-latest.md) - Use `watch` channel for sharing the latest value with multiple observers
- [`async-oneshot-response`](rules/async-oneshot-response.md) - Use `oneshot` channel for request-response patterns
- [`async-joinset-structured`](rules/async-joinset-structured.md) - Use `JoinSet` for managing dynamic collections of spawn


