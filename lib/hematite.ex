defmodule Flow.Hematite do
  use Rustler, otp_app: :flow, crate: "flow_hematite"

  def add(a), do: :erlang.nif_error(:nif_not_loaded)
end
