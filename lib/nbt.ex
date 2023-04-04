defmodule Flow.NBT do
  def read(data, type_id, size2) do
      # <<type_id::8, clam::size2>> = data]
      Flow.NBT.clam(8, 1, data)
  end

  defmacro clam(a: literal ,b: literal, c: expression) do
    quote do
      <<type_id::a, clam::b, data::binary>> = c
    end
  end
end
