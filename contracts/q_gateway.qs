import { Q_Asset, Quorum } from "quantova/primitives";
import { Registry } from "quantova/stdlib";
contract QGateway {
  asset QBRIDGED;
  state {
    operators: GuardianSet<9>;
    used_refs: Registry<Q_Hash>;
    minted_supply: u128;
    asset_cap: u128;
    epoch_minted: u128;
    epoch_cap: u128;
    confirmation_depth: u32;
    source_paused: bool;
    global_pause: bool;
  }
  genesis {
    operators = deploy_params.operators;
    asset_cap = deploy_params.asset_cap;
    epoch_cap = deploy_params.epoch_cap;
    confirmation_depth = deploy_params.confirmation_depth;
  }
  invariant minted_supply <= asset_cap;
  invariant epoch_minted <= epoch_cap;
  entry mint_deposit(deposit: DepositFact, approvals: Quorum<6 of 9, operators>)
    mints QBRIDGED
    writes(used_refs, minted_supply, epoch_minted)
    reads(operators, confirmation_depth, asset_cap, epoch_cap, source_paused, global_pause)
    denies global_pause
    denies source_paused
    denies used_refs.contains(deposit.reference)
    limits minted_supply + deposit.amount <= asset_cap
    limits epoch_minted + deposit.amount <= epoch_cap
  {
    guard deposit.amount > 0;
    guard deposit.finality_depth >= confirmation_depth;
    used_refs.insert(deposit.reference);
    minted_supply += deposit.amount;
    epoch_minted += deposit.amount;
    send(deposit.recipient, mint(deposit.amount));
    emit Minted(deposit.recipient, deposit.amount, deposit.reference, approvals.digest);
  }
  entry burn_exit(units: Q_Asset<QBRIDGED>, request: ExitRequest)
    burns QBRIDGED
    writes(minted_supply)
  {
    guard units.amount > 0;
    minted_supply -= units.amount;
    emit ExitRequested(caller, request.destination, units.amount);
  }
  entry report_reorg(report: ReorgReport, approvals: Quorum<6 of 9, operators>)
    writes(source_paused)
  {
    source_paused = 1;
    emit ReorgPaused(report.fork_depth, approvals.digest);
  }
  entry clear_reorg(order: ClearReorg, approvals: Quorum<6 of 9, operators>)
    writes(source_paused)
    after 24 hours from approvals.first
  {
    source_paused = 0;
    emit ReorgCleared(approvals.digest);
  }
  entry pause(approvals: Quorum<6 of 9, operators>)
    writes(global_pause)
  {
    global_pause = 1;
    emit GatewayPaused(approvals.digest);
  }
  entry unpause(approvals: Quorum<6 of 9, operators>)
    writes(global_pause)
    after 24 hours from approvals.first
  {
    global_pause = 0;
    emit GatewayUnpaused(approvals.digest);
  }
  entry roll_epoch(approvals: Quorum<6 of 9, operators>)
    writes(epoch_minted)
  {
    epoch_minted = 0;
    emit EpochRolled(approvals.digest);
  }
  event Minted(to: Q_Address, amount: u128, reference: Q_Hash, digest: Q_Hash);
  event ExitRequested(sender: Q_Address, destination: Q_Hash, amount: u128);
  event ReorgPaused(fork_depth: u32, digest: Q_Hash);
  event ReorgCleared(digest: Q_Hash);
  event GatewayPaused(digest: Q_Hash);
  event GatewayUnpaused(digest: Q_Hash);
  event EpochRolled(digest: Q_Hash);
}
