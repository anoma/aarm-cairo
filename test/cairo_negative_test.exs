defmodule NegativeTest do
  use ExUnit.Case

  doctest Cairo.CairoProver
  doctest Cairo.CairoVM

  test "cairo_vm_runner with invalid program content" do
    invalid_program = "This is not valid JSON"
    {:ok, input} = File.read("./native/cairo_vm/cairo_input.json")

    assert {:error, error_message} =
             Cairo.cairo_vm_runner(invalid_program, input)

    assert error_message == "Invalid program content"
  end

  test "cairo_vm_runner with invalid input JSON" do
    {:ok, program} = File.read("./native/cairo_vm/cairo.json")
    invalid_input = "This is not valid JSON"

    assert {:error, error_message} =
             Cairo.cairo_vm_runner(program, invalid_input)

    assert error_message == "Invalid input JSON"
  end

  test "cairo_vm_runner with runtime error in Cairo program" do
    program_with_error = ~S"""
    {"attributes":[],"builtins":["output","range_check","ec_op","poseidon"],"data":["0x4","0x48087ffd7fff8000","0x482a800080018000","0x48087ffb7fff8000","0x480880027fff8000","0x208b7fff7fff7ffe","0x4002800080007fff","0x4826800180008000","0x1","0x48107ffb7fff8000","0x48107ffb7fff8000","0x48107ffb7fff8000","0x10780017fff7fff","0x0"],"hints":{"8":[{"accessible_scopes":[],"code":"Input(y)","flow_tracking_data":{"ap_tracking":{"group":0,"offset":0},"reference_ids":{}}}],"9":[{"accessible_scopes":[],"code":"Input(x)","flow_tracking_data":{"ap_tracking":{"group":0,"offset":0},"reference_ids":{}}}]},"identifiers":{"__main__.__end__":{"pc":159,"type":"label"},"__main__.__start__":{"pc":0,"type":"label"},"__main__.main":{"decorators":[],"pc":0,"type":"function"}},"main_scope":"__main__","prime":"0x800000000000011000000000000000000000000000000000000000000000001","reference_manager":{"references":[]}}
    """

    input = "{}"

    assert {:error, error_message} =
             Cairo.cairo_vm_runner(program_with_error, input)

    assert String.starts_with?(error_message, "Runtime error:")
  end

  test "cairo_get_output" do
    assert {:error, _} = Cairo.get_output([])
    assert {:error, _} = Cairo.get_output([1, 2, 3, 4])
  end

  test "cairo_felt_to_string" do
    assert "0x0" = Cairo.felt_to_string(List.duplicate(0, 32))

    assert "0x7752582c54a42fe0fa35c40f07293bb7d8efe90e21d8d2c06a7db52d7d9b7a1" =
             Cairo.felt_to_string([
               7,
               117,
               37,
               130,
               197,
               74,
               66,
               254,
               15,
               163,
               92,
               64,
               240,
               114,
               147,
               187,
               125,
               142,
               254,
               144,
               226,
               29,
               141,
               44,
               6,
               167,
               219,
               82,
               215,
               217,
               183,
               161
             ])

    assert {:error, "Invalid finite field: 32 bytes needed"} =
             Cairo.felt_to_string([1, 2, 3, 4])
  end
end
