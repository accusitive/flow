defmodule Flow.Hematite do
  use Rustler, otp_app: :flow, crate: "flow_hematite"

  def read_and_discard_nbt(a), do: :erlang.nif_error(:nif_not_loaded)
end
