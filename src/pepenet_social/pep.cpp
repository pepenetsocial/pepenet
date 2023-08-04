#include "pep.h"
namespace pepenet_social {
  ibool pep_args::loadArgsFromJson()
  {
    if (!m_schema_valid)
    {
      return ibool{ false, std::string("Json schema has to be validated before args can be loaded") };
    }
    if (!m_json.HasMember("msg"))
    {
      return ibool{ false, std::string("json field msg is required!") };
    }
    else
    {
      m_msg = m_json["msg"].GetString();
    }
    if (m_json.HasMember("pseudonym"))
    {
      m_pseudonym = m_json["pseudonym"].GetString();
    }
    if (m_json.HasMember("sk_seed"))
    {
      if (!m_json.HasMember("post_pk"))
      {
        m_valid_args = false;
        return ibool{ false, std::string("json field post_pk is required when sk_seed is defined!") };
      }
      m_sk_seed = m_json["sk_seed"].GetString();
    }
    if (m_json.HasMember("post_pk"))
    {
      m_post_pk = m_json["post_pk"].GetBool();
      if (!m_json.HasMember("sk_seed"))
      {
        m_valid_args = false;
        return ibool{ false, std::string("json field sk_seed is required when post_pk is defined!") };
      }
    }
    if (m_json.HasMember("tx_ref"))
    {
      std::string tx_ref_hex = m_json["tx_ref"].GetString();
      crypto::hash tx_ref_parsed;
      if (!epee::string_tools::hex_to_pod(tx_ref_hex, tx_ref_parsed))
      {
        m_valid_args = false;
        return ibool{ false, std::string("unable to parse tx_ref from json!") };
      }
      m_tx_ref = tx_ref_parsed;
    }
    if (m_json.HasMember("pepetag"))
    {
      m_pepetag = m_json["pepetag"].GetString();
    }
    if (m_json.HasMember("donation_address"))
    {
      m_donation_address = m_json["donation_address"].GetString();
    }
    
    m_valid_args = true;
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep::loadFromSocialArgs(pep_args const& args)
  {
    if (!args.m_valid_args)
    {
      return ibool{ false, std::string("invalid social args") };
    }
    //copy base fields
    m_msg = args.m_msg;
    m_pseudonym = args.m_pseudonym;
    m_tx_ref = args.m_tx_ref;
    m_pepetag = args.m_pepetag;
    m_donation_address = args.m_donation_address;
    //create pep
    ibool r = dumpBaseToProto(); //base
    if (!r.b)
    {
      return r;
    }
    if (args.m_sk_seed.has_value()) //create sig
    {
      pepenet_social_protos::pep_base* base_ptr = m_proto.release_base(); //get base prt
      //get keys for signing
      crypto::public_key pk;
      crypto::secret_key sk;
      bool r = pepenet_social::secret_key_from_seed(args.m_sk_seed.value(), sk);
      if (!r)
      {
        return ibool{ r, std::string("failed to generate sk from sk_seed") };
      }
      r = crypto::secret_key_to_public_key(sk, pk);
      if (!r)
      {
        return ibool{ r, std::string("failed to generate pk from sk") };
      }
      //add pk to base if requested
      if (args.m_post_pk.value_or(false))
      {
        bytes pk_bytes(pk.data, 32);
        base_ptr->set_pk(pk_bytes);
      }
      //sign binary base
      bytes base_bytes;
      base_ptr->SerializeToString(&base_bytes);
      m_proto.set_allocated_base(base_ptr); //give base back to proto
      
      crypto::signature sig;
      pepenet_social::sign_msg(base_bytes, sig, pk, sk);
      //convert sig to bytes and set it to proto
      bytes sig_bytes = bytes(sig.c.data, 32) + bytes(sig.r.data, 32);
      //set the sig and pk
      m_proto.set_sig(sig_bytes);
      m_sig = sig;
      m_pk = pk;
    }
    return { true, INFO_NULLOPT };
  }

  ibool pep::dumpBaseToProto()
  {
    pepenet_social_protos::pep_base* base = new pepenet_social_protos::pep_base; //allocate to avoid destructor
    base->set_msg(m_msg);
    if (m_pseudonym.has_value())
    {
      base->set_pseudonym(m_pseudonym.value());
    }
    if (m_tx_ref.has_value())
    {
      base->set_tx_ref(std::string(m_tx_ref.value().data, 32));
    }
    if (m_pepetag.has_value())
    {
      base->set_pepetag(m_pepetag.value());
    }
    if (m_donation_address.has_value())
    {
      base->set_donation_address(m_donation_address.value());
    }
    m_proto.set_allocated_base(base);
    return { true, INFO_NULLOPT };
  }

  ibool pep::dumpToProto()
  {
    dumpBaseToProto();
    bytes sig_bytes = bytes(m_sig.value().c.data, 32) + bytes(m_sig.value().r.data, 32);
    m_proto.set_sig(sig_bytes);
    return { true, INFO_NULLOPT };
  }
  
  ibool pep::loadFromProto()
  {
    pepenet_social_protos::pep_base* base_ptr = m_proto.release_base();
    m_msg = base_ptr->msg();
    m_pseudonym = base_ptr->pseudonym();
    crypto::hash parsed_tx_ref;
    bool r = from_bytes(parsed_tx_ref, base_ptr->tx_ref());
    if (!r)
    {
      return ibool{ r, std::string("invalid tx_ref bytes in proto") };
    }
    else
    {
      m_tx_ref = parsed_tx_ref;
    }
    m_pepetag = base_ptr->pepetag();
    m_donation_address = base_ptr->donation_address();
    m_proto.set_allocated_base(base_ptr); //return base to proto;

    crypto::signature parsed_sig;
    r = from_bytes(parsed_sig, m_proto.sig());
    if (!r)
    {
      return ibool{ r, std::string("invalid sig bytes in proto") };
    }
    else
    {
      m_sig = parsed_sig;
    }

    m_loaded = true;
    return ibool{ true, INFO_NULLOPT };
  }

  ibool pep::validate()
  {
    if (!m_loaded)
    {
      return ibool{ false, std::string("proto not loaded") };
    }
    //verify fields
    std::string compressed_msg;
    bool r = lzma_compress_msg(m_msg, compressed_msg);
    if (m_msg.empty() || compressed_msg.size() > LZMA_PEP_MAX_SIZE);
    {
      return ibool{ false, std::string("invalid msg field") };
    }
    if (m_pseudonym.has_value())
    {
      if (m_pseudonym.value().empty() || m_pseudonym.value().size() > PSEUDONYM_MAX_SIZE)
      {
        return ibool{ false, std::string("invalid pseudonym field") };
      }
    }
    if (m_pepetag.has_value())
    {
      if (m_pepetag.value().empty() || m_pepetag.value().size() > PEPETAG_MAX_SIZE)
      {
        return ibool{ false, std::string("invalid pepetag field") };
      }
    }
    if (m_donation_address.has_value())
    {
      if (m_donation_address.value().empty() || m_donation_address.value().size() > DONATION_ADDRESS_MAX_SIZE)
      {
        return ibool{ false, std::string("invalid pepetag field") };
      }
    }
    
    if (m_sig.has_value()) //verify base
    {
      if (!m_pk.has_value())
      {
        return ibool{ false, std::string("missing pk in pep. can't validate") };
      }
      pepenet_social_protos::pep_base* base_ptr = m_proto.release_base();
      bytes base_bytes;
      if (!base_ptr->SerializeToString(&base_bytes))
      {
        return ibool{ false, std::string("failed to serialize pep base") };
      }
      m_proto.set_allocated_base(base_ptr);
      //verify sig
      if (!check_msg_sig(base_bytes, m_sig.value(), m_pk.value()))
      {
        return ibool{ false, std::string("failed to verify pep: invalid sig") };
      }
    }
    return ibool{ true, INFO_NULLOPT};
  }

  ibool pep::validate(const boost::optional<crypto::public_key>& pk)
  {
    m_pk = pk;
    ibool r = validate();
    m_pk.reset();
    return r;
  }

  ibool add_pep_to_tx_extra(const pepenet_social::pep& pep, std::vector<uint8_t>& tx_extra)
  {
    bytes lzma_pep;
    pepenet_social::pep p = pep;
    ibool r = p.dumpToBinary(lzma_pep);
    if (!r.b)
    {
      return r;
    }
    if (!cryptonote::add_lzma_pep_to_tx_extra(tx_extra, lzma_pep))
    {
      return ibool{ false, std::string("failed to add pep to tx_extra") };
    }
    return ibool{ true, INFO_NULLOPT };
  }

  ibool get_and_verify_pep_from_tx_extra(const boost::optional<crypto::public_key>& ver_pk, boost::optional<pepenet_social::pep>& pep, const std::vector<uint8_t>& tx_extra)
  {
    //init pep optional
    pep = pepenet_social::pep();
    std::string lzma_pep;
    bool pep_missing = !cryptonote::get_lzma_pep_from_tx_extra(tx_extra, lzma_pep);
    if (!pep_missing)
    {
      bytes pep_proto_bytes;
      bool decomp = pepenet_social::lzma_decompress_msg(lzma_pep, pep_proto_bytes);
      if (!decomp)
      {
        pep.reset(); //decompression failed - invalid tx
        return ibool{ false, std::string("failed to decompress lzma pep from tx_extra") };
      }
      ibool r = pep.value().loadFromBinary(pep_proto_bytes);
      if (!r.b)
      {
        return ibool{ false, std::string("failed to load pep proto from bytes in tx_extra") };
      }
      r = pep.value().validate(ver_pk.value());
      if (!r.b)
      {
        return r;
      }
      return ibool{ true, INFO_NULLOPT };
    }
    else
    {
      pep.reset();
    }
    return { true, INFO_NULLOPT };
  }
}