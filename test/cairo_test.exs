defmodule NifTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_prove_test" do
    {:ok, program} = File.read("./juvix/cairo.json")
    {:ok, input} = File.read("./juvix/cairo_input.json")

    {output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    assert "17\n" = output

    # Prove and verify
    {proof, public_input} = Cairo.prove(trace, memory, vm_public_input)
    assert true = Cairo.verify(proof, public_input)

    # Get program hash
    _program_hash =
      Cairo.get_program_hash(public_input) |> Cairo.felt_to_string()

    # IO.inspect(program_hash)

    assert {:error, _} = Cairo.prove([], memory, vm_public_input)
    assert {:error, _} = Cairo.prove(trace, [], vm_public_input)
    assert {:error, _} = Cairo.prove(trace, memory, [])
    assert {:error, _} = Cairo.prove([1], memory, vm_public_input)
    assert {:error, _} = Cairo.prove(trace, [1], vm_public_input)
    assert {:error, _} = Cairo.prove(trace, memory, [1])
    assert {:error, _} = Cairo.verify([], public_input)
    assert {:error, _} = Cairo.verify(proof, [])
    assert {:error, _} = Cairo.verify([1], public_input)
    assert {:error, _} = Cairo.verify(proof, [1])
  end
end
