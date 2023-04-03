defmodule FlowTest do
  use ExUnit.Case
  doctest Flow

  test "greets the world" do
    assert Flow.hello() == :world
  end
end
