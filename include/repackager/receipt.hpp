#pragma once

#include "repackager/error.hpp"
#include "repackager/json.hpp"
#include "repackager/models.hpp"

#include <filesystem>
#include <string>

namespace repackager {

Json receipt_to_json(const Receipt& receipt);
Expected<Receipt> receipt_from_json(const Json& json);

std::string serialize_receipt(const Receipt& receipt);
Expected<Receipt> parse_receipt(std::string_view text);

Status write_receipt_file(const std::filesystem::path& path, const Receipt& receipt);
Expected<Receipt> read_receipt_file(const std::filesystem::path& path);

// Authoritative store: %LOCALAPPDATA%\Repackager\receipts\<package-name>\receipt.json
std::filesystem::path authoritative_receipt_path(std::string_view package_name);
Status write_authoritative_receipt(const Receipt& receipt);
Expected<Receipt> load_authoritative_receipt(std::string_view package_name);

std::filesystem::path layout_receipt_path(const std::filesystem::path& output_root);
std::filesystem::path inplace_receipt_path(const std::filesystem::path& directory,
                                           std::string_view package_name);

}  // namespace repackager
