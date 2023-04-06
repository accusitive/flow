defmodule Flow.Versions do
  def get_version(pv) do
    case pv do
      762 -> :MC_1_19_4
      761 -> :MC_1_19_3
      760 -> :MC_1_19_1
      759 -> :MC_1_19
      758 -> :MC_1_18_2
      757 -> :MC_1_18
      756 -> :MC_1_17_1
      755 -> :MC_1_17
      754 -> :MC_1_16_4
      753 -> :MC_1_16_3
      751 -> :MC_1_16_2
      736 -> :MC_1_16_1
      735 -> :MC_1_16
      _ -> :UNKNOWN
    end
  end

  def session(version) do
    case version do
      :MC_1_19_4 -> 0x06
      _ -> -1
    end
  end
  def respawn(version) do
    case version do
      :MC_1_19_4 -> 0x41
      :MC_1_19_3 -> 0x3D
      :MC_1_19_1 -> 0x3E
      _ -> raise "UndefinedPacket respawn (#{version})"
    end
  end
  def plugin_message(version) do
    case version do
      :MC_1_19_4 -> 0x17
      :MC_1_19_3 -> 0x15
      :MC_1_19_1 -> 0x16
      _ -> raise "UndefinedPacket Plugin (#{version})"
    end
  end
end
