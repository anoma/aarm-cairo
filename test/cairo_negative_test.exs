defmodule NegativeTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_vm_runner with invalid program content" do
    invalid_program = "This is not valid JSON"
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    assert {:error, error_message} = Cairo.cairo_vm_runner(invalid_program, input)
    assert error_message == "Invalid program content"
  end

  test "cairo_vm_runner with invalid input JSON" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    invalid_input = "This is not valid JSON"

    assert {:error, error_message} = Cairo.cairo_vm_runner(program, invalid_input)
    assert error_message == "Invalid input JSON"
  end

  test "cairo_vm_runner with runtime error in Cairo program" do
    program_with_error = ~S"""
    {"attributes":[],"builtins":["output","range_check","ec_op","poseidon"],"data":["0x4","0x48087ffd7fff8000","0x482a800080018000","0x48087ffb7fff8000","0x480880027fff8000","0x208b7fff7fff7ffe","0x4002800080007fff","0x4826800180008000","0x1","0x48107ffb7fff8000","0x48107ffb7fff8000","0x48107ffb7fff8000","0x10780017fff7fff","0x0"],"hints":{"8":[{"accessible_scopes":[],"code":"Input(y)","flow_tracking_data":{"ap_tracking":{"group":0,"offset":0},"reference_ids":{}}}],"9":[{"accessible_scopes":[],"code":"Input(x)","flow_tracking_data":{"ap_tracking":{"group":0,"offset":0},"reference_ids":{}}}]},"identifiers":{"__main__.__end__":{"pc":159,"type":"label"},"__main__.__start__":{"pc":0,"type":"label"},"__main__.main":{"decorators":[],"pc":0,"type":"function"}},"main_scope":"__main__","prime":"0x800000000000011000000000000000000000000000000000000000000000001","reference_manager":{"references":[]}}
    """
    input = "{}"

    assert {:error, error_message} = Cairo.cairo_vm_runner(program_with_error, input)
    assert String.starts_with?(error_message, "Runtime error:")
  end

  test "cairo_prove with invalid trace (RegisterStatesError)" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    {_output, _trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    invalid_trace = [0, 1, 2, 3]

    assert {:error, error_message} = Cairo.prove(invalid_trace, memory, vm_public_input)
    assert String.starts_with?(error_message, "Register states error:")
  end

  test "cairo_prove with invalid memory (CairoMemoryError)" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    {_output, trace, _memory, vm_public_input} =
      Cairo.cairo_vm_runner(
        program,
        input
      )

    invalid_memory = [0, 1, 2, 3]

    assert {:error, error_message} = Cairo.prove(trace, invalid_memory, vm_public_input)
    assert String.starts_with?(error_message, "Cairo memory error:")
  end

  test "cairo_verify with invalid proof" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    {_output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(program, input)

    {_proof, public_input} = Cairo.prove(trace, memory, vm_public_input)
    invalid_proof = [0, 1, 2, 3]

    assert {:error, error_message} = Cairo.verify(invalid_proof, public_input)
    assert String.starts_with?(error_message, "Proof decoding error:")
  end

  test "cairo_verify with invalid public input" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    {_output, trace, memory, vm_public_input} =
      Cairo.cairo_vm_runner(program, input)

    {proof, _public_input} = Cairo.prove(trace, memory, vm_public_input)
    invalid_public_input = []

    assert {:error, error_message} = Cairo.verify(proof, invalid_public_input)
    assert String.starts_with?(error_message, "Public input decoding error:")
  end
end