/*
 * libkeepass - KeePass key database importer/exporter
 * Copyright (C) 2014 Christian Kindahl
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fstream>

#include <gtest/gtest.h>

#include "kdbx.hh"
#include "key.hh"

using namespace keepass;

namespace {

std::string GetTestPath(const std::string& name) {
  return "./test/data/kdbx/" + name;
}

std::string GetTestJson(const std::string& name) {
  std::ifstream file(GetTestPath(name));
  std::string file_str((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());

  // Compact the JSON by removing all white space not present in string
  // literals.
  char quote = '\0';
  std::string json;
  for (char c : file_str) {
    if (quote != '\0') {
      if (c == quote)
        quote = '\0';

      json.push_back(c);
    } else if (c == '"' || c == '\'') {
      quote = c;
      json.push_back(c);
    } else if (!std::isspace<char>(c, std::locale::classic())) {
      json.push_back(c);
    }
  }

  return json;
}

}   // namespace

TEST(KdbxTest, CorrectPassword) {
  Key key("password");

  KdbxFile file;
  EXPECT_NO_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key));
}

TEST(KdbxTest, InvalidPassword) {
  Key key("wrong_password");

  KdbxFile file;
  EXPECT_THROW(file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key),
               std::runtime_error);
}

TEST(KdbxTest, ImportGroups1) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-1-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-1-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups2) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-3-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-2-random_entry-4-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-2-random_entry-4-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups3) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-3-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-3-random_entry-1-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups4) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-4-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-4-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups5) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-5-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-5-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups6) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-6-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-6-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups7) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-empty-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-1-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-1-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-2-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-2-pw-aes.json"));

  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-7-random_entry-3-pw-aes.kdbx"), key);
  });
  root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-7-random_entry-3-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups8) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-8-empty-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-8-empty-pw-aes.json"));
}

TEST(KdbxTest, ImportGroups9) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("groups-9-default-pw-aes.kdbx"), key);
  });
  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("groups-9-default-pw-aes.json"));
}

TEST(KdbxTest, ImportComplex1) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-pw-aes.kdbx"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes.json"));
}

TEST(KdbxTest, ImportComplex1Compressed) {
  Key key("password");

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-pw-aes-gzip.kdbx"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-pw-aes-gzip.json"));
}

TEST(KdbxTest, ImportComplex1KeyFile) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key-aes.kdbx"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-aes.json"));
}

TEST(KdbxTest, ImportComplex1KeyFileCompressed) {
  Key key;
  key.SetKeyFile(GetTestPath("complex-1-key-aes-gzip.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key-aes-gzip.kdbx"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key-aes-gzip.json"));
}

TEST(KdbxTest, ImportComplex1KeyFileAndPassword) {
  Key key("password");
  key.SetKeyFile(GetTestPath("complex-1-key_pw-aes.key"));

  KdbxFile file;
  std::unique_ptr<Database> db;
  EXPECT_NO_THROW({
    db = file.Import(GetTestPath("complex-1-key_pw-aes.kdbx"), key);
  });

  std::shared_ptr<Group> root = db->root().lock();
  EXPECT_NE(root, nullptr);
  EXPECT_EQ(root->ToJson(), GetTestJson("complex-1-key_pw-aes.json"));
}
