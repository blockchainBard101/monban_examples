module game_core::hero;

use monban::monban::{Self, AccessRegistry, AdminCap, Witness};
use std::string::String;

public struct HERO has drop {}

public struct Hero has key, store {
    id: UID,
    name: String,
    level: u64,
    experience: u64,
}

fun init(otw: HERO, ctx: &mut TxContext) {
    monban::create_and_claim(otw, ctx);
}

public fun create_hero(name: String, ctx: &mut TxContext): Hero {
    Hero {
        id: object::new(ctx),
        name,
        level: 1,
        experience: 0,
    }
}

public fun level_up(hero: &mut Hero, registry: &AccessRegistry, witness: Witness) {
    monban::verify_access(registry, witness);
    hero.level = hero.level + 1;
}

public fun whitelist_package(
    admin_cap: &AdminCap,
    registry: &mut AccessRegistry,
    package_id: String,
) {
    monban::whitelist_package(registry, admin_cap, package_id);
}
