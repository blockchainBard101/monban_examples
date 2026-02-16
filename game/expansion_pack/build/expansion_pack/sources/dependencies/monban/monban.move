/// # Monban Access Control Library
///
/// This module provides a comprehensive access control system for Sui blockchain applications.
/// It allows package administrators to create registries that whitelist specific packages,
/// enabling fine-grained access control across different modules and packages.
///
/// ## Key Features
///
/// - Package whitelisting and blacklisting
/// - Admin capability management
/// - Access verification for protected functions
/// - Registry-based access control
///
/// ## Quick Start
///
/// ```move
/// // 1. In your package's init function, create a registry
/// fun init(otw: MY_MODULE, ctx: &mut TxContext) {
///     monban::create_and_claim(otw, ctx);
/// }
///
/// // 2. Whitelist a package using the AdminCap you received
/// monban::whitelist_package(&mut registry, &admin_cap, string::utf8(b"0x1234..."));
///
/// // 3. Guard any protected function with verify_access
/// public fun protected_fn<W: drop>(registry: &AccessRegistry, w: W) {
///     let witness = monban::create_witness(w);
///     monban::verify_access(&registry, witness);
///     // ... rest of your logic
/// }
/// ```
module monban::monban;

use std::type_name;
use sui::types;
use std::string::{Self, String};

// ===== Error Constants =====

/// Thrown when `create_registry` or `create_and_claim` is called with a type
/// that is not a one-time witness. Only types instantiated in a package `init`
/// function qualify.
const ENotOneTimeWitness: u64 = 0;

/// Thrown by `verify_access` when the calling package's ID is not present
/// in the registry's whitelist.
const EUnauthorized: u64 = 0;

/// Thrown by `whitelist_package` when the provided package ID already exists
/// in the registry. Each package may only appear once.
const EPackageAlreadyWhitelisted: u64 = 1;

/// Thrown by `remove_package` when the provided package ID does not exist
/// in the registry's whitelist.
const EPackageNotWhitelisted: u64 = 2;

/// Thrown when the `AdminCap` passed to a mutating function does not belong
/// to the target `AccessRegistry`.
const EInvalidAdmin: u64 = 3;

// ===== Structs =====

/// Shared on-chain registry that tracks which packages are allowed access.
///
/// An `AccessRegistry` is created once per package (via `create_registry` or
/// `create_and_claim`) and published as a shared object, meaning any transaction
/// can read it. Only the holder of the associated `AdminCap` can mutate it.
///
/// All package IDs stored inside use the canonical `"0x"` prefixed hex format.
///
/// ## Example
///
/// ```move
/// // Reading the registry in a protected function
/// public fun my_fn(registry: &AccessRegistry, ...) {
///     let witness = monban::create_witness(MyWitness {});
///     monban::verify_access(registry, witness);
/// }
/// ```
public struct AccessRegistry has key, store {
    /// Unique on-chain identifier for this registry object.
    id: UID,
    /// `"0x"` prefixed package ID of the package that originally created this registry.
    package: String,
    /// Name of the Move module that created this registry.
    module_name: String,
    /// Address of the account considered the admin of this registry.
    /// This is set to `ctx.sender()` at creation time and is informational —
    /// actual authority is enforced by `AdminCap`.
    admin: address,
    /// Ordered list of `"0x"` prefixed package IDs that are permitted access.
    /// Use `whitelist_package` / `remove_package` to mutate this list.
    whitelisted_packages: vector<String>,
}

/// Proof-of-authority token that gates all mutations on an `AccessRegistry`.
///
/// Returned by `create_registry` and transferred to the caller by `create_and_claim`.
/// The `registry_id` field ties this cap to exactly one registry — passing it to
/// a different registry will abort with `EInvalidAdmin`.
///
/// Destroy permanently and irrevocably with `burn_admin_cap`.
public struct AdminCap has key, store {
    /// Unique on-chain identifier for this capability object.
    id: UID,
    /// Object address of the `AccessRegistry` this capability controls.
    registry_id: address,
}

/// Single-use proof that a specific package is making the current call.
///
/// Created with `create_witness` from a drop-type value belonging to the calling
/// package, then consumed by `verify_access`. Because Move's type system guarantees
/// that only code within a package can construct its own types, this serves as an
/// unforgeable identity token.
public struct Witness has drop, store {
    /// `"0x"` prefixed package ID extracted from the witness type at runtime.
    package_id_str: String,
}

// ===== Public Functions =====

/// Constructs a `Witness` that identifies the package defining type `W`.
///
/// The package address is resolved at runtime via `type_name::with_original_ids`,
/// so it always reflects the actual deployed address even across package upgrades.
/// The resulting `Witness` is intended to be passed directly to `verify_access`.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `_w` | `W: drop` | A value of any drop type defined in the calling package. The value itself is discarded — only its type is used to extract the package ID. |
///
/// ## Returns
///
/// A `Witness` whose `package_id_str` is the `"0x"` prefixed address of the
/// package that defines `W`.
///
/// ## Example
///
/// ```move
/// // Inside package "0xCAFE..."
/// public struct MyWitness has drop {}
///
/// public fun call_protected(registry: &AccessRegistry) {
///     let w = monban::create_witness(MyWitness {});
///     monban::verify_access(registry, w);
/// }
/// ```
public fun create_witness<W: drop>(_w: W): Witness {
    let package_id = type_name::with_original_ids<W>().address_string();
    let package_id_str = string::from_ascii(package_id);
    Witness { package_id_str: add_prefix(package_id_str) }
}

/// Creates a new `AccessRegistry` and returns the `AdminCap` for managing it.
///
/// This function must be called from your package's `init` function because
/// `OTW` must be a one-time witness — a type that the Sui runtime guarantees
/// can only ever be instantiated once, during `init`.
///
/// The new registry is automatically published as a shared object so that any
/// transaction can read from it. The returned `AdminCap` is the only way to
/// mutate the registry after creation.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `otw` | `OTW: drop` | One-time witness for the calling package, proving this is `init`. |
/// | `ctx` | `&mut TxContext` | Transaction context used to mint object IDs and read the sender. |
///
/// ## Returns
///
/// An `AdminCap` linked to the newly created registry. Transfer it to the
/// desired admin address or store it as needed.
///
/// ## Errors
///
/// | Code | Constant | Condition |
/// |------|----------|-----------|
/// | `0` | `ENotOneTimeWitness` | `otw` is not a valid one-time witness type. |
///
/// ## Example
///
/// ```move
/// fun init(otw: MY_PACKAGE, ctx: &mut TxContext) {
///     let admin_cap = monban::create_registry(otw, ctx);
///     transfer::public_transfer(admin_cap, ctx.sender());
/// }
/// ```
public fun create_registry<OTW: drop>(otw: OTW, ctx: &mut TxContext): AdminCap {
    assert!(types::is_one_time_witness(&otw), ENotOneTimeWitness);

    let type_name = type_name::with_original_ids<OTW>();
    let package_id_str = string::from_ascii(type_name.address_string());

    let registry_uid = object::new(ctx);
    let registry_id = object::uid_to_address(&registry_uid);

    let registry = AccessRegistry {
        id: registry_uid,
        package: add_prefix(package_id_str),
        module_name: string::from_ascii(type_name.module_string()),
        admin: ctx.sender(),
        whitelisted_packages: vector::empty(),
    };

    let admin_cap = AdminCap {
        id: object::new(ctx),
        registry_id,
    };

    transfer::public_share_object(registry);
    admin_cap
}

/// Creates a registry and immediately sends the `AdminCap` to the transaction sender.
///
/// This is a one-liner convenience wrapper around `create_registry`. Use it when
/// your `init` function doesn't need to do anything special with the `AdminCap`
/// other than own it.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `otw` | `OTW: drop` | One-time witness for the calling package. |
/// | `ctx` | `&mut TxContext` | Transaction context. |
///
/// ## Errors
///
/// | Code | Constant | Condition |
/// |------|----------|-----------|
/// | `0` | `ENotOneTimeWitness` | `otw` is not a valid one-time witness type. |
///
/// ## Example
///
/// ```move
/// fun init(otw: MY_PACKAGE, ctx: &mut TxContext) {
///     monban::create_and_claim(otw, ctx);
///     // AdminCap is now in the sender's wallet
/// }
/// ```
#[allow(lint(self_transfer))]
public fun create_and_claim<OTW: drop>(otw: OTW, ctx: &mut TxContext) {
    transfer::public_transfer(create_registry(otw, ctx), ctx.sender());
}

/// Adds a package to the registry's whitelist, granting it access.
///
/// After this call, `verify_access` calls from the whitelisted package will
/// succeed. The `package_id` must be a `"0x"` prefixed hex string, matching the
/// format produced by `create_witness`.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `registry` | `&mut AccessRegistry` | The registry to modify. |
/// | `admin_cap` | `&AdminCap` | Proof of admin rights over this registry. |
/// | `package_id` | `String` | `"0x"` prefixed package ID to whitelist. |
///
/// ## Errors
///
/// | Code | Constant | Condition |
/// |------|----------|-----------|
/// | `3` | `EInvalidAdmin` | `admin_cap` does not belong to this registry. |
/// | `1` | `EPackageAlreadyWhitelisted` | The package is already in the whitelist. |
///
/// ## Example
///
/// ```move
/// monban::whitelist_package(
///     &mut registry,
///     &admin_cap,
///     string::utf8(b"0xCAFEBABE..."),
/// );
/// ```
public fun whitelist_package(
    registry: &mut AccessRegistry,
    admin_cap: &AdminCap,
    package_id: String,
) {
    assert!(admin_cap.registry_id == object::uid_to_address(&registry.id), EInvalidAdmin);
    assert!(
        !registry.whitelisted_packages.contains(&package_id),
        EPackageAlreadyWhitelisted,
    );
    registry.whitelisted_packages.push_back(package_id);
}

/// Removes a package from the registry's whitelist, revoking its access.
///
/// After this call, any `verify_access` call from the removed package will
/// abort with `EUnauthorized`. The package must be currently whitelisted.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `registry` | `&mut AccessRegistry` | The registry to modify. |
/// | `admin_cap` | `&AdminCap` | Proof of admin rights over this registry. |
/// | `package_id` | `String` | `"0x"` prefixed package ID to remove. |
///
/// ## Errors
///
/// | Code | Constant | Condition |
/// |------|----------|-----------|
/// | `3` | `EInvalidAdmin` | `admin_cap` does not belong to this registry. |
/// | `2` | `EPackageNotWhitelisted` | The package is not in the whitelist. |
public fun remove_package(
    registry: &mut AccessRegistry,
    admin_cap: &AdminCap,
    package_id: String,
) {
    assert!(admin_cap.registry_id == object::uid_to_address(&registry.id), EInvalidAdmin);

    let (found, index) = vector::index_of(&registry.whitelisted_packages, &package_id);
    assert!(found, EPackageNotWhitelisted);

    registry.whitelisted_packages.remove(index);
}

/// Asserts that the package encoded in `witness` is whitelisted in the registry.
///
/// This is the core access-control gate. Call it at the top of any function that
/// should be restricted to authorised packages. If the check passes, execution
/// continues normally. If it fails, the entire transaction is aborted.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `registry` | `&AccessRegistry` | The registry to check against. |
/// | `witness` | `Witness` | Unforgeable proof of the calling package's identity, produced by `create_witness`. |
///
/// ## Errors
///
/// | Code | Constant | Condition |
/// |------|----------|-----------|
/// | `0` | `EUnauthorized` | The calling package is not in the whitelist. |
///
/// ## Example
///
/// ```move
/// public fun sensitive_action<W: drop>(registry: &AccessRegistry, w: W) {
///     monban::verify_access(registry, monban::create_witness(w));
///     // Only reachable if the caller's package is whitelisted
/// }
/// ```
public fun verify_access(registry: &AccessRegistry, witness: Witness) {
    let is_whitelisted = registry.whitelisted_packages.contains(&witness.package_id_str);
    assert!(is_whitelisted, EUnauthorized);
}

/// Permanently destroys an `AdminCap`, irrevocably removing admin rights.
///
/// Once burned, no one can ever mutate the associated `AccessRegistry` again
/// (add or remove packages). This is useful for "locking" a registry into a
/// final state. **This action cannot be undone.**
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `self` | `AdminCap` | The capability to destroy (consumed). |
public fun burn_admin_cap(self: AdminCap) {
    let AdminCap { id, registry_id: _ } = self;
    id.delete();
}

/// Returns `true` if the given package ID is currently whitelisted.
///
/// The `"0x"` prefix is added automatically — you may pass either a raw hex
/// string or one that already includes the prefix (though double-prefixing will
/// not match and will return `false`).
///
/// This is a read-only helper. For enforcing access control in transactions,
/// use `verify_access` instead.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `registry` | `&AccessRegistry` | The registry to inspect. |
/// | `package_id` | `String` | Package ID to look up (raw hex, without `"0x"`). |
///
/// ## Returns
///
/// `true` if the package is whitelisted; `false` otherwise.
public fun is_whitelisted(registry: &AccessRegistry, package_id: String): bool {
    registry.whitelisted_packages.contains(&add_prefix(package_id))
}

/// Returns a snapshot of all currently whitelisted package IDs.
///
/// Each element is a `"0x"` prefixed string. The vector is a **copy** —
/// modifying it has no effect on the registry's internal state.
///
/// ## Parameters
///
/// | Name | Type | Description |
/// |------|------|-------------|
/// | `registry` | `&AccessRegistry` | The registry to query. |
///
/// ## Returns
///
/// `vector<String>` — a copy of the whitelisted package list.
public fun get_whitelisted_packages(registry: &AccessRegistry): vector<String> {
    registry.whitelisted_packages
}

// ===== Private Helpers =====

/// Prepends `"0x"` to a raw hex string to produce a canonical package ID.
///
/// All IDs stored in the registry use this normalised format. This helper is
/// called internally whenever a raw address string needs to be prepared for
/// storage or lookup.
fun add_prefix(s: String): String {
    let mut prefix = string::utf8(b"0x");
    prefix.append(s);
    prefix
}