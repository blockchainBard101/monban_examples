module treasury::treasury;

use monban::monban::{Self, AccessRegistry, AdminCap, Witness};
use std::string::String;
use sui::balance::{Self, Balance};
use sui::coin::{Self, Coin};
use sui::sui::SUI;

public struct TREASURY has drop {}

public struct Treasury has key {
    id: UID,
    bal: Balance<SUI>,
}

fun init(otw: TREASURY, ctx: &mut TxContext) {
    monban::create_and_claim(otw, ctx);

    let treasury = Treasury {
        id: object::new(ctx),
        bal: balance::zero(),
    };
    transfer::share_object(treasury);
}

public fun whitelist_package(
    admin_cap: &AdminCap,
    registry: &mut AccessRegistry,
    package_id: String,
) {
    monban::whitelist_package(registry, admin_cap, package_id);
}

public fun add_to_treasury(treasury: &mut Treasury, payment: Coin<SUI>) {
    balance::join(&mut treasury.bal, coin::into_balance(payment));
}

public fun withdraw_from_treasury(
    treasury: &mut Treasury,
    registry: &AccessRegistry,
    witness: Witness,
    amount: u64,
    ctx: &mut TxContext,
): Coin<SUI> {
    monban::verify_access(registry, witness);
    let withdrawn = balance::split(&mut treasury.bal, amount);
    coin::from_balance(withdrawn, ctx)
}
