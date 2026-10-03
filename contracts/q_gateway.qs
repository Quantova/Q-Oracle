import { Q_Net, Q_Origin, Q_Address, Q_Hash, Q_Height, Quorum, Attestation, Watch } from "quantova/primitives";
import { GuardianSet, Registry, Map } from "quantova/stdlib";

domain ATTEST = "QUANTOVA/Q-ORACLE/ATTEST/v1";
domain REORG = "QUANTOVA/Q-ORACLE/REORG/v1";
domain TIER = "QUANTOVA/Q-ORACLE/TIER/v1";
domain FREEZE = "QUANTOVA/Q-ORACLE/FREEZE/v1";
domain WATCHDOG = "QUANTOVA/Q-ORACLE/WATCHDOG/v1";
domain BATCH = "QUANTOVA/Q-ORACLE/BATCH/v1";
domain EPOCH = "QUANTOVA/Q-ORACLE/EPOCH/v1";

const DEPOSIT: u8 = 0;
const BASE_TIER: u8 = 1;
const WATCHDOG_WINDOW: Q_Height = 7200;
const WATCHDOG_COOLDOWN: Q_Height = 57600;
const RESUME_SKEW: Q_Height = 16;
const RESUME_WINDOW: Q_Height = 600;

record DepositFact {
  version: u8;
  source: Q_Net;
  dest: Q_Net;
  route: u32;
  direction: u8;
  nonce: u64;
  reference: Q_Hash;
  origin: Q_Origin;
  amount: u128;
  recipient: Q_Address;
  finality_depth: u32;
  observed_height: u64;
  expiry_height: u64;
}

record BatchMarker { net: Q_Net; index: u64; dest: Q_Net; era: u64; }
record TierChange { net: Q_Net; tier: u8; dest: Q_Net; era: u64; }
record FreezeOrder { until: Q_Height; dest: Q_Net; era: u64; }
record WatchAlarm { until: Q_Height; dest: Q_Net; era: u64; }
record ReorgReport { net: Q_Net; fork_depth: u32; at_height: Q_Height; dest: Q_Net; era: u64; }
record ResumeOrder { net: Q_Net; at_height: Q_Height; dest: Q_Net; era: u64; }
record PauseOrder { dest: Q_Net; era: u64; nonce: u64; }
record EpochOrder { dest: Q_Net; era: u64; nonce: u64; }
record ExitRequest { destination: Q_Hash; }
record ExitTicket { id: u64; origin: Q_Origin; amount: u128; destination: Q_Hash; unlock: Q_Height; }

contract QGateway {
  asset Bridged<Q_Origin>;
  state {
    network: Q_Net;
    era: u64;
    operators: GuardianSet<9>;
    governance: GuardianSet<7>;
    used_refs: Registry<(Q_Net, Q_Hash)>;
    watchdog_last: Map<Q_Address, Q_Height>;
    paused_since: Map<Q_Net, Q_Height>;
    gov_nonce: u64;
    corridor_depth: Map<Q_Net, u32>;
    corridor_quorum: Map<Q_Net, u16>;
    corridor_tier: Map<Q_Net, u8>;
    corridor_active: Map<Q_Net, bool>;
    corridor_cursor: Map<Q_Net, u64>;
    minted: Map<Q_Origin, u128>;
    caps: Map<Q_Origin, u128>;
    epoch_minted: u128;
    epoch_cap: u128;
    exit_delay: Q_Height;
    exits: Map<u64, ExitTicket>;
    next_exit_id: u64;
    frozen_until: Q_Height;
    source_paused: Map<Q_Net, bool>;
    global_pause: bool;
  }
  genesis {
    network = deploy_params.network;
    era = deploy_params.era;
    operators = deploy_params.operators;
    governance = deploy_params.governance;
    corridor_depth = deploy_params.corridor_depth;
    corridor_quorum = deploy_params.corridor_quorum;
    corridor_tier = deploy_params.corridor_tier;
    corridor_active = deploy_params.corridor_active;
    caps = deploy_params.caps;
    epoch_cap = deploy_params.epoch_cap;
    exit_delay = deploy_params.exit_delay;
    frozen_until = 0;
    next_exit_id = 0;
    global_pause = false;
    gov_nonce = 0;
  }
  invariant forall origin: minted[origin] <= caps[origin];
  invariant epoch_minted <= epoch_cap;

  entry mint_deposit(deposit: DepositFact, attestation: Attestation<operators, ATTEST>)
    mints Bridged
    writes(used_refs, minted, epoch_minted)
    reads(network, operators, corridor_depth, corridor_quorum, corridor_active, caps, epoch_cap, source_paused, global_pause, frozen_until)
    denies global_pause
    denies now < frozen_until
    denies now > deposit.expiry_height
    denies deposit.is_zero
    denies source_paused[deposit.source]
    denies used_refs.contains((deposit.source, deposit.reference))
    limits minted[deposit.origin] + deposit.amount <= caps[deposit.origin]
    limits epoch_minted + deposit.amount <= epoch_cap
  {
    guard deposit.version == 1;
    guard deposit.direction == DEPOSIT;
    guard deposit.dest == network;
    guard deposit.amount > 0;
    guard corridor_active[deposit.source];
    guard deposit.finality_depth >= corridor_depth[deposit.source];
    guard attestation.over(deposit);
    guard attestation.distinct >= corridor_quorum[deposit.source];
    guard attestation.distinct >= 6;
    used_refs.insert((deposit.source, deposit.reference));
    minted[deposit.origin] += deposit.amount;
    epoch_minted += deposit.amount;
    send(deposit.recipient, mint(deposit.origin, deposit.amount));
    emit Minted(deposit.recipient, deposit.origin, deposit.amount, deposit.reference, attestation.digest);
  }

  entry accept_batch(marker: BatchMarker, attestation: Attestation<operators, BATCH>)
    writes(corridor_cursor)
    reads(operators, corridor_quorum, corridor_active, global_pause, frozen_until)
    denies global_pause
    denies now < frozen_until
    denies source_paused[marker.net]
  {
    guard marker.dest == network;
    guard marker.era == era;
    guard corridor_active[marker.net];
    guard attestation.over(marker);
    guard attestation.distinct >= corridor_quorum[marker.net];
    guard attestation.distinct >= 6;
    guard marker.index == corridor_cursor[marker.net];
    corridor_cursor[marker.net] = marker.index + 1;
    emit BatchAccepted(marker.net, marker.index, attestation.digest);
  }

  entry request_exit(units: Bridged<origin>, request: ExitRequest)
    burns Bridged
    writes(minted, exits, next_exit_id)
    reads(exit_delay)
  {
    guard units.amount > 0;
    guard minted[units.origin] >= units.amount;
    minted[units.origin] -= units.amount;
    exits[next_exit_id] = ExitTicket {
      id: next_exit_id,
      origin: units.origin,
      amount: units.amount,
      destination: request.destination,
      unlock: now + exit_delay,
    };
    emit ExitRequested(caller, next_exit_id, units.origin, units.amount, now + exit_delay);
    next_exit_id += 1;
  }

  entry finalize_exit(id: u64)
    writes(exits)
    reads(global_pause, frozen_until)
    denies global_pause
    denies now < frozen_until
  {
    guard exits.contains(id);
    guard now >= exits[id].unlock;
    emit ExitFinalized(exits[id].id, exits[id].origin, exits[id].amount, exits[id].destination);
    exits.remove(id);
  }

  entry raise_tier(change: TierChange, approvals: Quorum<5 of 7, governance, TIER>)
    writes(corridor_tier)
    reads(governance, corridor_active)
  {
    guard change.dest == network;
    guard change.era == era;
    guard corridor_active[change.net];
    guard change.tier > corridor_tier[change.net];
    corridor_tier[change.net] = change.tier;
    emit TierRaised(change.net, change.tier, approvals.digest);
  }

  entry emergency_freeze(order: FreezeOrder, approvals: Quorum<6 of 9, operators, FREEZE>)
    writes(frozen_until)
    reads(operators)
  {
    guard order.dest == network;
    guard order.era == era;
    guard order.until > frozen_until;
    frozen_until = order.until;
    emit Frozen(order.until, approvals.digest);
  }

  entry watchdog_freeze(alarm: WatchAlarm, watch: Watch<1 of operators, WATCHDOG>)
    writes(frozen_until, watchdog_last)
    reads(operators, watchdog_last)
    denies now < watchdog_last[watch.signer] + WATCHDOG_COOLDOWN
    denies now < frozen_until
  {
    guard alarm.dest == network;
    guard alarm.era == era;
    guard alarm.until > now;
    guard alarm.until <= now + WATCHDOG_WINDOW;
    guard alarm.until > frozen_until;
    watchdog_last[watch.signer] = now;
    frozen_until = alarm.until;
    emit WatchdogFroze(watch.signer, alarm.until);
  }

  entry report_reorg(report: ReorgReport, approvals: Quorum<6 of 9, operators, REORG>)
    writes(source_paused, paused_since)
    reads(network, era)
    denies report.at_height > now + RESUME_SKEW
    denies now > report.at_height + RESUME_WINDOW
  {
    guard report.dest == network;
    guard report.era == era;
    source_paused[report.net] = true;
    paused_since[report.net] = now;
    emit ReorgPaused(report.net, report.fork_depth, approvals.digest);
  }

  entry clear_reorg(order: ResumeOrder, approvals: Quorum<6 of 9, operators, REORG>)
    writes(source_paused)
    reads(network, era, source_paused)
    denies order.at_height > now + RESUME_SKEW
    denies now > order.at_height + RESUME_WINDOW
    after 24 hours from approvals.first
  {
    guard order.dest == network;
    guard order.era == era;
    guard source_paused[order.net];
    source_paused[order.net] = false;
    emit ReorgCleared(order.net, approvals.digest);
  }

  entry pause(order: PauseOrder, approvals: Quorum<6 of 9, operators, FREEZE>)
    writes(global_pause, gov_nonce)
    reads(network, era, gov_nonce)
  {
    guard order.dest == network;
    guard order.era == era;
    guard order.nonce == gov_nonce;
    gov_nonce += 1;
    global_pause = true;
    emit GatewayPaused(approvals.digest);
  }

  entry unpause(order: PauseOrder, approvals: Quorum<6 of 9, operators, FREEZE>)
    writes(global_pause, gov_nonce)
    reads(network, era, gov_nonce)
    after 24 hours from approvals.first
  {
    guard order.dest == network;
    guard order.era == era;
    guard order.nonce == gov_nonce;
    gov_nonce += 1;
    global_pause = false;
    emit GatewayUnpaused(approvals.digest);
  }

  entry roll_epoch(order: EpochOrder, approvals: Quorum<6 of 9, operators, EPOCH>)
    writes(epoch_minted, gov_nonce)
    reads(network, era, gov_nonce)
    after 24 hours from approvals.first
  {
    guard order.dest == network;
    guard order.era == era;
    guard order.nonce == gov_nonce;
    gov_nonce += 1;
    epoch_minted = 0;
    emit EpochRolled(approvals.digest);
  }

  event Minted(to: Q_Address, origin: Q_Origin, amount: u128, reference: Q_Hash, digest: Q_Hash);
  event BatchAccepted(net: Q_Net, index: u64, digest: Q_Hash);
  event ExitRequested(sender: Q_Address, id: u64, origin: Q_Origin, amount: u128, unlock: Q_Height);
  event ExitFinalized(id: u64, origin: Q_Origin, amount: u128, destination: Q_Hash);
  event TierRaised(net: Q_Net, tier: u8, digest: Q_Hash);
  event Frozen(until: Q_Height, digest: Q_Hash);
  event WatchdogFroze(signer: Q_Address, until: Q_Height);
  event ReorgPaused(net: Q_Net, fork_depth: u32, digest: Q_Hash);
  event ReorgCleared(net: Q_Net, digest: Q_Hash);
  event GatewayPaused(digest: Q_Hash);
  event GatewayUnpaused(digest: Q_Hash);
  event EpochRolled(digest: Q_Hash);
}
