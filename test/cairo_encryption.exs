defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_encryption_test" do
    {:ok, program} = File.read("./native/cairo_vm/encryption.json")
    {:ok, input} = File.read("./native/cairo_vm/encryption_input.json")

    {output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    IO.inspect(output)

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, vm_public_input)
    assert true = Cairo.verify(proof, public_input)

  end
end
